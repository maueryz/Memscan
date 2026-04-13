package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image/color"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/sys/windows"
)

// ====================== 中文修复（极简，无依赖）======================
var chineseFontResource fyne.Resource

func init() {
	fontPath := "C:\\Windows\\Fonts\\msyh.ttc"
	fontData, err := ioutil.ReadFile(fontPath)
	if err == nil {
		chineseFontResource = &fyne.StaticResource{
			StaticName:    "msyh.ttc",
			StaticContent: fontData,
		}
	} else {
		chineseFontResource = theme.DefaultTextFont()
	}
}

type chineseTheme struct{}

func (c chineseTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	return theme.LightTheme().Color(name, variant)
}
func (c chineseTheme) Font(style fyne.TextStyle) fyne.Resource { return chineseFontResource }
func (c chineseTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.LightTheme().Icon(name)
}
func (c chineseTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.LightTheme().Size(name)
}

// ====================================================================

// --- 系统常量与结构体（不动）---
const (
	TCP_TABLE_OWNER_PID_ALL = 5
	AF_INET                 = 2
	PROCESS_QUERY_INFO      = 0x0400
	PROCESS_VM_READ         = 0x0010
	MEM_COMMIT              = 0x1000
	PAGE_READWRITE          = 0x04
	PAGE_EXECUTE_READWRITE  = 0x40
	MAX_HITS_PER_PROCESS    = 5
	MAX_MEMORY_REGION_SIZE  = 500 * 1024 * 1024
)

type MIB_TCPROW_OWNER_PID struct {
	State, LocalAddr, LocalPort, RemoteAddr, RemotePort, OwningPid uint32
}

type ScanHit struct {
	ProcessName string
	PID         uint32
	Before      string
	Match       string
	After       string
	Connections []string
}

var (
	allScanResults  []ScanHit
	modIphlpapi     = syscall.NewLazyDLL("iphlpapi.dll")
	procGetTCPTable = modIphlpapi.NewProc("GetExtendedTcpTable")
)

// ====================== 双模式入口（GUI + 命令行）======================
func main() {
	// 强制软件渲染 → 解决Win7/Server2008/无显卡环境跑不动问题
	os.Setenv("FYNE_RENDERER", "software")

	// ====================== 命令行模式（新增）======================
	// 用法：Memscan.exe cli 关键词
	if len(os.Args) >= 3 && os.Args[1] == "cli" {
		keyword := os.Args[2]
		fmt.Println("==================================")
		fmt.Println("Memscan 命令行模式")
		fmt.Println("扫描关键词：", keyword)
		fmt.Println("==================================")

		// 复用原有核心扫描逻辑，100%功能一致
		netMap := getNetworkMap()
		results := scanMemoryWithNet(keyword, false, false, netMap)

		if len(results) == 0 {
			fmt.Println("[+] 未扫描到匹配结果")
			return
		}

		// 控制台输出结果
		for _, hit := range results {
			fmt.Printf("\n[进程] %s (PID: %d)\n", hit.ProcessName, hit.PID)
			if len(hit.Connections) > 0 {
				fmt.Printf("[外联] %v\n", hit.Connections)
			}
			fmt.Printf("[内容] ...%s[%s]%s...\n", hit.Before, hit.Match, hit.After)
		}
		return
	}

	// ====================== 原有GUI模式（完全未改动！）======================
	myApp := app.New()
	myApp.Settings().SetTheme(&chineseTheme{})
	myWindow := myApp.NewWindow("Memscan")
	myWindow.Resize(fyne.NewSize(950, 700))
	myWindow.CenterOnScreen()

	// --- UI 组件定义（不动）---
	searchInput := widget.NewEntry()
	searchInput.SetPlaceHolder("输入检索关键词...")

	fuzzyCheck := widget.NewCheck("正则", nil)
	caseCheck := widget.NewCheck("区分大小写", nil)
	mergeCheck := widget.NewCheck("PID合并", nil)
	mergeCheck.SetChecked(true)
	onlyNetCheck := widget.NewCheck("仅外联", nil)

	filterInput := widget.NewEntry()
	filterInput.SetPlaceHolder("在结果中过滤进程或PID...")
	filterInput.Disable()

	resultBox := container.NewVBox()
	scrollArea := container.NewVScroll(resultBox)

	// --- 核心渲染函数（仅优化卡顿，其余100%原样）---
	var renderResults func()
	renderResults = func() {
		resultBox.Objects = nil
		filterText := strings.ToLower(filterInput.Text)

		var filtered []ScanHit
		for _, h := range allScanResults {
			if onlyNetCheck.Checked && len(h.Connections) == 0 {
				continue
			}
			pidStr := fmt.Sprintf("%d", h.PID)
			if filterText == "" || strings.Contains(strings.ToLower(h.ProcessName), filterText) || strings.Contains(pidStr, filterText) {
				filtered = append(filtered, h)
			}
		}

		if len(filtered) == 0 && len(allScanResults) > 0 {
			resultBox.Add(widget.NewLabel("未找到匹配过滤条件的记录"))
		}

		if mergeCheck.Checked {
			type Group struct {
				Name  string
				Conns []string
				Hits  []ScanHit
			}
			groups := make(map[uint32]*Group)
			var pids []uint32
			for _, h := range filtered {
				if _, ok := groups[h.PID]; !ok {
					groups[h.PID] = &Group{h.ProcessName, h.Connections, []ScanHit{}}
					pids = append(pids, h.PID)
				}
				groups[h.PID].Hits = append(groups[h.PID].Hits, h)
			}
			for _, pid := range pids {
				g := groups[pid]
				titleStr := fmt.Sprintf("进程: %s [PID: %d] (%d 条匹配)", g.Name, pid, len(g.Hits))
				if len(g.Conns) > 0 {
					titleStr += "   [存在外联]"
				}
				isOpen := false
				var btn *widget.Button
				content := container.NewVBox()
				content.Hide()

				btn = widget.NewButton("+ "+titleStr, func() {
					isOpen = !isOpen
					if isOpen {
						if len(content.Objects) == 0 {
							if len(g.Conns) > 0 {
								connRt := widget.NewRichText(&widget.TextSegment{
									Text:  "    [*] 活跃外联: " + strings.Join(g.Conns, " | "),
									Style: widget.RichTextStyle{ColorName: theme.ColorNamePrimary, TextStyle: fyne.TextStyle{Bold: true, Italic: true}},
								})
								connRt.Wrapping = fyne.TextWrapWord
								content.Add(connRt)
								content.Add(widget.NewSeparator())
							}
							for _, hit := range g.Hits {
								rt := widget.NewRichText(
									&widget.TextSegment{Text: hit.Before, Style: widget.RichTextStyleCodeInline},
									&widget.TextSegment{Text: hit.Match, Style: widget.RichTextStyle{ColorName: theme.ColorNameError, TextStyle: fyne.TextStyle{Bold: true}}},
									&widget.TextSegment{Text: hit.After + "\n", Style: widget.RichTextStyleCodeInline},
								)
								rt.Wrapping = fyne.TextWrapBreak
								content.Add(rt)
							}
						}
						content.Show()
						btn.SetText("- " + titleStr)
					} else {
						content.Hide()
						btn.SetText("+ " + titleStr)
					}
				})
				btn.Alignment = widget.ButtonAlignLeading
				btn.Importance = widget.LowImportance
				resultBox.Add(container.NewVBox(btn, content, widget.NewSeparator()))
			}
		} else {
			for _, h := range filtered {
				headerText := fmt.Sprintf("[!] 进程: %s (PID: %d)", h.ProcessName, h.PID)
				segments := []widget.RichTextSegment{
					&widget.TextSegment{Text: headerText + "\n", Style: widget.RichTextStyleStrong},
				}
				if len(h.Connections) > 0 {
					segments = append(segments, &widget.TextSegment{
						Text:  "    [*] 活跃外联: " + strings.Join(h.Connections, " | ") + "\n",
						Style: widget.RichTextStyle{ColorName: theme.ColorNamePrimary, TextStyle: fyne.TextStyle{Bold: true, Italic: true}},
					})
				}
				// 修复笔误：hit → h
				segments = append(segments,
					&widget.TextSegment{Text: h.Before, Style: widget.RichTextStyleCodeInline},
					&widget.TextSegment{Text: h.Match, Style: widget.RichTextStyle{ColorName: theme.ColorNameError, TextStyle: fyne.TextStyle{Bold: true}}},
					&widget.TextSegment{Text: h.After + "\n", Style: widget.RichTextStyleCodeInline},
				)
				rt := widget.NewRichText(segments...)
				rt.Wrapping = fyne.TextWrapBreak
				resultBox.Add(container.NewVBox(rt, widget.NewSeparator()))
			}
		}
		resultBox.Refresh()
	}

	mergeCheck.OnChanged = func(bool) { renderResults() }
	onlyNetCheck.OnChanged = func(bool) { renderResults() }
	filterInput.OnSubmitted = func(_ string) { renderResults() }

	// --- 导出功能（不动）---
	exportBtn := widget.NewButtonWithIcon("导出结果", theme.DocumentSaveIcon(), func() {
		if len(allScanResults) == 0 {
			return
		}
		d := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err == nil && writer != nil {
				defer writer.Close()
				var b bytes.Buffer
				b.WriteString("=== 内存检索结果 ===\n时间: " + time.Now().Format("2006-01-02 15:04:05") + "\n\n")
				for _, h := range allScanResults {
					b.WriteString(fmt.Sprintf("[%s PID:%d]\n外联: %v\n上下文: ...%s[%s]%s...\n\n", h.ProcessName, h.PID, h.Connections, h.Before, h.Match, h.After))
				}
				writer.Write(b.Bytes())
			}
		}, myWindow)
		d.SetFileName("Audit_Report.txt")
		d.Show()
	})
	exportBtn.Disable()

	// --- 扫描按钮（不动）---
	var scanBtn *widget.Button
	scanBtn = widget.NewButtonWithIcon("立即扫描", theme.SearchIcon(), func() {
		keyword := searchInput.Text
		if keyword == "" {
			return
		}
		if fuzzyCheck.Checked {
			if _, err := regexp.Compile(keyword); err != nil {
				dialog.ShowError(fmt.Errorf("无效正则: %v", err), myWindow)
				return
			}
		}

		scanBtn.Disable()
		scanBtn.SetText("分析中...")
		resultBox.Objects = []fyne.CanvasObject{widget.NewLabel("正在检索系统内存并关联网络信息...")}

		go func() {
			netMap := getNetworkMap()
			tempData := scanMemoryWithNet(keyword, fuzzyCheck.Checked, caseCheck.Checked, netMap)

			time.Sleep(100 * time.Millisecond)
			allScanResults = tempData

			if len(allScanResults) > 0 {
				exportBtn.Enable()
				filterInput.Enable()
			}
			renderResults()
			scanBtn.Enable()
			scanBtn.SetText("立即扫描")
		}()
	})
	scanBtn.Importance = widget.HighImportance

	// --- 布局组合（不动）---
	topArea := container.NewVBox(
		widget.NewLabelWithStyle("内存检索工具", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		searchInput,
		container.NewHBox(fuzzyCheck, caseCheck, mergeCheck, onlyNetCheck, layout.NewSpacer(), scanBtn, exportBtn),
		widget.NewSeparator(),
		container.NewBorder(nil, nil, widget.NewLabel("结果过滤(回车生效):"), nil, filterInput),
		widget.NewSeparator(),
	)

	myWindow.SetContent(container.NewBorder(topArea, nil, nil, nil, scrollArea))
	myWindow.ShowAndRun()
}

// --- 底层网络与内存函数（100%未改动）---
func getNetworkMap() map[uint32][]string {
	netMap := make(map[uint32][]string)
	var size uint32
	procGetTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(AF_INET), uintptr(TCP_TABLE_OWNER_PID_ALL), 0)
	if size == 0 {
		return netMap
	}
	buffer := make([]byte, size)
	ret, _, _ := procGetTCPTable.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(AF_INET), uintptr(TCP_TABLE_OWNER_PID_ALL), 0)
	if ret != 0 {
		return netMap
	}
	numEntries := binary.LittleEndian.Uint32(buffer[0:4])
	entrySize := int(unsafe.Sizeof(MIB_TCPROW_OWNER_PID{}))
	for i := 0; i < int(numEntries); i++ {
		offset := 4 + i*entrySize
		if offset+entrySize > len(buffer) {
			break
		}
		row := (*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&buffer[offset]))
		if row.RemoteAddr != 0 {
			rIP := make(net.IP, 4)
			binary.LittleEndian.PutUint32(rIP, row.RemoteAddr)
			rPort := ((row.RemotePort & 0xff00) >> 8) | ((row.RemotePort & 0x00ff) << 8)
			netMap[row.OwningPid] = append(netMap[row.OwningPid], fmt.Sprintf("%s:%d", rIP.String(), rPort))
		}
	}
	return netMap
}

func scanMemoryWithNet(keyword string, isFuzzy, isCase bool, netMap map[uint32][]string) []ScanHit {
	var results []ScanHit
	sBytes := []byte(keyword)
	if len(sBytes) == 0 {
		return nil
	}
	if !isCase && !isFuzzy {
		sBytes = toLowerASCII(sBytes)
	}
	var regex *regexp.Regexp
	if isFuzzy {
		prefix := ""
		if !isCase {
			prefix = "(?i)"
		}
		regex, _ = regexp.Compile(prefix + keyword)
	}
	snapshot, _ := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	defer windows.CloseHandle(snapshot)
	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))
	if err := windows.Process32First(snapshot, &procEntry); err != nil {
		return nil
	}
	for {
		pid := procEntry.ProcessID
		if pid > 4 {
			h, err := windows.OpenProcess(PROCESS_QUERY_INFO|PROCESS_VM_READ, false, pid)
			if err == nil {
				exe := syscall.UTF16ToString(procEntry.ExeFile[:])
				hits := searchInProcess(h, exe, pid, sBytes, regex, isFuzzy, isCase)
				if len(hits) > 0 {
					if conns, ok := netMap[pid]; ok {
						for i := range hits {
							hits[i].Connections = conns
						}
					}
					results = append(results, hits...)
				}
				windows.CloseHandle(h)
			}
		}
		if err := windows.Process32Next(snapshot, &procEntry); err != nil {
			break
		}
	}
	return results
}

func searchInProcess(h windows.Handle, exe string, pid uint32, sBytes []byte, reg *regexp.Regexp, isFuzzy, isCase bool) []ScanHit {
	var hits []ScanHit
	var addr uintptr
	var mem windows.MemoryBasicInformation
	for {
		if len(hits) >= MAX_HITS_PER_PROCESS {
			break
		}
		if err := windows.VirtualQueryEx(h, addr, &mem, unsafe.Sizeof(mem)); err != nil {
			break
		}
		if mem.State == MEM_COMMIT && mem.RegionSize < MAX_MEMORY_REGION_SIZE && (mem.Protect == PAGE_READWRITE || mem.Protect == PAGE_EXECUTE_READWRITE) {
			buf := make([]byte, mem.RegionSize)
			var n uintptr
			if err := windows.ReadProcessMemory(h, addr, &buf[0], mem.RegionSize, &n); err == nil && n > 0 {
				chunk := buf[:n]
				sChunk := chunk
				if !isFuzzy && !isCase {
					sChunk = toLowerASCII(chunk)
				}
				offset := 0
				for len(hits) < MAX_HITS_PER_PROCESS {
					start, end := -1, -1
					if isFuzzy && reg != nil {
						loc := reg.FindIndex(chunk[offset:])
						if loc != nil {
							start, end = offset+loc[0], offset+loc[1]
						}
					} else {
						idx := bytes.Index(sChunk[offset:], sBytes)
						if idx != -1 {
							start, end = offset+idx, offset+idx+len(sBytes)
						}
					}
					if start != -1 && end > start {
						b, m, a := extractCtx(chunk, start, end)
						hits = append(hits, ScanHit{ProcessName: exe, PID: pid, Before: b, Match: m, After: a})
						offset = end
					} else {
						break
					}
				}
			}
		}
		oldAddr := addr
		addr += uintptr(mem.RegionSize)
		if addr <= oldAddr {
			break
		}
	}
	return hits
}

func extractCtx(c []byte, s, e int) (string, string, string) {
	if s < 0 || e > len(c) || s > e {
		return "", "", ""
	}
	s1 := s - 64
	if s1 < 0 {
		s1 = 0
	}
	e1 := e + 64
	if e1 > len(c) {
		e1 = len(c)
	}
	return sanitize(c[s1:s]), sanitize(c[s:e]), sanitize(c[e:e1])
}

func sanitize(d []byte) string {
	r := make([]byte, len(d))
	for i, b := range d {
		if b >= 32 && b <= 126 {
			r[i] = b
		} else {
			r[i] = '.'
		}
	}
	return string(r)
}

func toLowerASCII(d []byte) []byte {
	r := make([]byte, len(d))
	for i, b := range d {
		if b >= 'A' && b <= 'Z' {
			r[i] = b + 32
		} else {
			r[i] = b
		}
	}
	return r
}
