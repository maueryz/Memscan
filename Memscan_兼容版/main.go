package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image/color"
	"io/ioutil"
	"math"
	"net"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/sys/windows"
)

// ====================== 全局配置常量 =======================
const (
	// 虚拟滚动预加载缓冲区
	PRELOAD_BUFFER_LINES = 3
	// 单条折叠行固定高度
	SINGLE_COLLAPSED_LINE_HEIGHT = 50
	// 单进程最大命中数
	MAX_HITS_PER_PROCESS = 5
	// Windows API 系统常量
	TCP_TABLE_OWNER_PID_ALL   = 5
	AF_INET                   = 2
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_READ           = 0x0010
	MEM_COMMIT                = 0x1000
	PAGE_READWRITE            = 0x04
	PAGE_EXECUTE_READWRITE    = 0x40
	MAX_MEMORY_REGION_SIZE    = 500 * 1024 * 1024
)

// ====================== 中文渲染修复（完全容错版）======================
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
		chineseFontResource = nil
	}
}

type chineseTheme struct{}

func (c chineseTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	return theme.DefaultTheme().Color(name, variant)
}
func (c chineseTheme) Font(style fyne.TextStyle) fyne.Resource {
	if chineseFontResource != nil {
		return chineseFontResource
	}
	return theme.DefaultTheme().Font(style)
}
func (c chineseTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}
func (c chineseTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}

// ====================== 数据结构体 =======================
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

type ProcessGroup struct {
	PID               uint32
	Name              string
	Conns             []string
	Hits              []ScanHit
	cachedFullContent *fyne.Container
	isExpanded        bool
}

// ====================== 全局变量 =======================
var (
	allScanResults  []ScanHit
	modIphlpapi     = syscall.NewLazyDLL("iphlpapi.dll")
	procGetTCPTable = modIphlpapi.NewProc("GetExtendedTcpTable")
)

// ====================== 单行彩色标题（100%兼容v2.2.0）======================
func buildSingleLineColorTitle(isExpanded bool, hasConn bool, pid uint32, procName string, hitCount int, onTap func()) fyne.CanvasObject {
	// 1. 标题背景，占满整行
	bgRect := canvas.NewRectangle(theme.ButtonColor())
	bgRect.SetMinSize(fyne.NewSize(0, 38))

	// 2. 标题分段组件列表
	var titleSegments []fyne.CanvasObject

	// 展开/收起前缀：[+]/[-]
	prefixText := "[+]"
	if isExpanded {
		prefixText = "[-]"
	}
	prefixLabel := canvas.NewText(prefixText, theme.ForegroundColor())
	titleSegments = append(titleSegments, prefixLabel)

	// 外联告警标记 <!> → 红色加粗
	if hasConn {
		warnText := canvas.NewText("<!>", theme.ErrorColor())
		warnText.TextStyle = fyne.TextStyle{Bold: true}
		titleSegments = append(titleSegments, warnText)
	}

	// 标题主体：进程{PID:XXXX} : 进程名（
	baseText := fmt.Sprintf("进程{PID:%d} : %s（", pid, procName)
	baseLabel := canvas.NewText(baseText, theme.ForegroundColor())
	titleSegments = append(titleSegments, baseLabel)

	// 匹配条数数字 → 蓝色加粗
	countText := canvas.NewText(fmt.Sprintf("%d", hitCount), theme.PrimaryColor())
	countText.TextStyle = fyne.TextStyle{Bold: true}
	titleSegments = append(titleSegments, countText)

	// 标题结尾：条匹配）
	suffixLabel := canvas.NewText("条匹配）", theme.ForegroundColor())
	titleSegments = append(titleSegments, suffixLabel)

	// 水平拼接所有标题分段
	titleHBox := container.NewHBox(titleSegments...)

	// 3. 透明点击层，占满整行
	clickBtn := widget.NewButton("", onTap)
	clickBtn.Importance = widget.LowImportance

	// 4. 三层叠放，整行点击有效
	return container.NewMax(
		bgRect,
		container.NewPadded(titleHBox),
		clickBtn,
	)
}

// ====================== 程序主入口 =======================
func main() {
	// 强制软件渲染，适配老系统
	os.Setenv("FYNE_RENDERER", "software")

	// CLI命令行模式
	if len(os.Args) >= 3 && os.Args[1] == "cli" {
		keyword := os.Args[2]
		fmt.Println("==================================")
		fmt.Println("Memscan 命令行模式")
		fmt.Println("扫描关键词：", keyword)
		fmt.Println("==================================")

		netMap := getNetworkMap()
		results := scanMemoryWithNet(keyword, false, false, netMap)

		if len(results) == 0 {
			fmt.Println("[+] 未扫描到匹配结果")
			return
		}

		for _, hit := range results {
			fmt.Printf("\n[进程名] %s\n[PID] %d\n", hit.ProcessName, hit.PID)
			if len(hit.Connections) > 0 {
				fmt.Printf("[外联地址] %v\n", hit.Connections)
			}
			fmt.Printf("[匹配上下文] ...%s%s%s...\n", hit.Before, hit.Match, hit.After)
		}
		return
	}

	// GUI模式初始化
	var processGroups []*ProcessGroup
	var lastScrollY float32 = 0

	myApp := app.New()
	myApp.Settings().SetTheme(&chineseTheme{})
	myWindow := myApp.NewWindow("Memscan")
	myWindow.Resize(fyne.NewSize(950, 700))
	myWindow.CenterOnScreen()

	// UI组件
	searchInput := widget.NewEntry()
	searchInput.SetPlaceHolder("请输入检索关键词...")

	fuzzyCheck := widget.NewCheck("正则匹配", nil)
	caseCheck := widget.NewCheck("区分大小写", nil)
	mergeCheck := widget.NewCheck("PID合并", nil)
	mergeCheck.SetChecked(true)
	onlyNetCheck := widget.NewCheck("仅显示外联进程", nil)

	filterInput := widget.NewEntry()
	filterInput.SetPlaceHolder("输入进程名/PID过滤结果...")
	filterInput.Disable()

	resultBox := container.NewVBox()
	scrollArea := container.NewVScroll(resultBox)

	// ====================== 核心渲染逻辑 =======================
	var dynamicRender func()
	var resetAndRender func()

	calculateRenderRange := func() (startIdx, endIdx int) {
		if len(processGroups) == 0 {
			return 0, 0
		}
		viewHeight := scrollArea.Size().Height
		if viewHeight <= 0 {
			viewHeight = 600
		}
		scrollY := scrollArea.Offset.Y
		currentTopLine := int(math.Floor(float64(scrollY) / SINGLE_COLLAPSED_LINE_HEIGHT))
		visibleLines := int(math.Ceil(float64(viewHeight) / SINGLE_COLLAPSED_LINE_HEIGHT))
		startIdx = currentTopLine - PRELOAD_BUFFER_LINES
		endIdx = currentTopLine + visibleLines + PRELOAD_BUFFER_LINES
		if startIdx < 0 {
			startIdx = 0
		}
		if endIdx > len(processGroups) {
			endIdx = len(processGroups)
		}
		return startIdx, endIdx
	}

	dynamicRender = func() {
		if len(processGroups) == 0 {
			return
		}
		startIdx, endIdx := calculateRenderRange()
		resultBox.Objects = nil

		// 顶部占位
		if startIdx > 0 {
			topSpacer := canvas.NewRectangle(color.Transparent)
			topSpacer.SetMinSize(fyne.NewSize(1, float32(startIdx)*SINGLE_COLLAPSED_LINE_HEIGHT))
			resultBox.Add(topSpacer)
		}

		// 渲染可视范围内的进程
		for i := startIdx; i < endIdx; i++ {
			g := processGroups[i]
			hasConn := len(g.Conns) > 0
			hitCount := len(g.Hits)

			// 生成单行标题
			titleContainer := buildSingleLineColorTitle(g.isExpanded, hasConn, g.PID, g.Name, hitCount, func() {
				g.isExpanded = !g.isExpanded
				if g.isExpanded && g.cachedFullContent == nil {
					g.cachedFullContent = container.NewVBox()
					// ========== 【最终无报错版：原生普通Entry，自动展开，清晰不淡】==========
					if hasConn {
						connFullText := "    [ ! ] 活跃外联地址: " + strings.Join(g.Conns, " | ")
						connEntry := widget.NewMultiLineEntry()
						connEntry.SetText(connFullText)
						connEntry.Wrapping = fyne.TextWrapWord
						// 不做任何禁用、不设置颜色、不设置透明度
						// 原生显示 → 最清晰、最兼容、绝对不报错
						g.cachedFullContent.Add(connEntry)
						g.cachedFullContent.Add(widget.NewSeparator())
					}

					// ========== 命中内容完全不变 ==========
					for hitIdx, hit := range g.Hits {
						fullText := fmt.Sprintf("...%s%s%s...", hit.Before, hit.Match, hit.After)
						rt := widget.NewRichText(
							&widget.TextSegment{Text: "...", Style: widget.RichTextStyleCodeInline},
							&widget.TextSegment{Text: hit.Before, Style: widget.RichTextStyleCodeInline},
							&widget.TextSegment{Text: hit.Match, Style: widget.RichTextStyle{ColorName: theme.ColorNameError, TextStyle: fyne.TextStyle{Bold: true}}},
							&widget.TextSegment{Text: hit.After, Style: widget.RichTextStyleCodeInline},
							&widget.TextSegment{Text: "...", Style: widget.RichTextStyleCodeInline},
						)
						rt.Wrapping = fyne.TextWrapWord

						copyBtn := widget.NewButtonWithIcon("复制", theme.ContentCopyIcon(), func() {
							if len(myApp.Driver().AllWindows()) > 0 {
								myApp.Driver().AllWindows()[0].Clipboard().SetContent(fullText)
							}
						})
						copyBtn.Importance = widget.MediumImportance
						hitRow := container.NewBorder(nil, nil, nil, copyBtn, rt)
						g.cachedFullContent.Add(hitRow)
						if hitIdx < len(g.Hits)-1 {
							g.cachedFullContent.Add(widget.NewSeparator())
						}
					}
				}
				dynamicRender()
			})

			// 进程行容器
			processRow := container.NewVBox()
			processRow.Add(titleContainer)
			if g.isExpanded && g.cachedFullContent != nil {
				processRow.Add(g.cachedFullContent)
			}
			processRow.Add(widget.NewSeparator())
			resultBox.Add(processRow)
		}

		// 底部占位
		if endIdx < len(processGroups) {
			bottomSpacer := canvas.NewRectangle(color.Transparent)
			bottomSpacer.SetMinSize(fyne.NewSize(1, float32(len(processGroups)-endIdx)*SINGLE_COLLAPSED_LINE_HEIGHT))
			resultBox.Add(bottomSpacer)
		}
		resultBox.Refresh()
	}

	resetAndRender = func() {
		resultBox.Objects = nil
		lastScrollY = 0
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

		if len(filtered) == 0 {
			if len(allScanResults) > 0 {
				resultBox.Add(widget.NewLabel("未找到匹配过滤条件的记录"))
			} else {
				resultBox.Add(widget.NewLabel("暂无扫描结果，请先点击【立即扫描】"))
			}
			processGroups = nil
			resultBox.Refresh()
			return
		}

		if mergeCheck.Checked {
			groups := make(map[uint32]*ProcessGroup)
			var pids []uint32
			for _, h := range filtered {
				if _, ok := groups[h.PID]; !ok {
					groups[h.PID] = &ProcessGroup{
						PID:               h.PID,
						Name:              h.ProcessName,
						Conns:             h.Connections,
						Hits:              []ScanHit{},
						cachedFullContent: nil,
						isExpanded:        false,
					}
					pids = append(pids, h.PID)
				}
				groups[h.PID].Hits = append(groups[h.PID].Hits, h)
			}
			processGroups = nil
			for _, pid := range pids {
				processGroups = append(processGroups, groups[pid])
			}
		} else {
			processGroups = nil
			for _, h := range filtered {
				processGroups = append(processGroups, &ProcessGroup{
					PID:               h.PID,
					Name:              h.ProcessName,
					Conns:             h.Connections,
					Hits:              []ScanHit{h},
					cachedFullContent: nil,
					isExpanded:        false,
				})
			}
		}
		dynamicRender()
	}

	// 事件绑定
	scrollArea.OnScrolled = func(offset fyne.Position) {
		if math.Abs(float64(offset.Y-lastScrollY)) > SINGLE_COLLAPSED_LINE_HEIGHT/2 {
			lastScrollY = offset.Y
			dynamicRender()
		}
	}
	mergeCheck.OnChanged = func(bool) { resetAndRender() }
	onlyNetCheck.OnChanged = func(bool) { resetAndRender() }
	filterInput.OnSubmitted = func(_ string) { resetAndRender() }

	// 导出功能
	exportBtn := widget.NewButtonWithIcon("导出报告", theme.DocumentSaveIcon(), func() {
		if len(allScanResults) == 0 {
			dialog.ShowInformation("提示", "暂无扫描结果，无法导出", myWindow)
			return
		}
		d := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil {
				dialog.ShowError(err, myWindow)
				return
			}
			if writer == nil {
				return
			}
			defer writer.Close()
			var b bytes.Buffer
			b.WriteString("=== 内存检索审计报告 ===\n")
			b.WriteString("扫描时间: " + time.Now().Format("2006-01-02 15:00:05") + "\n\n")
			for _, h := range allScanResults {
				b.WriteString(fmt.Sprintf("[进程名] %s\n[PID] %d\n[外联地址] %v\n[匹配上下文] ...%s%s%s...\n\n",
					h.ProcessName, h.PID, h.Connections, h.Before, h.Match, h.After))
			}
			_, _ = writer.Write(b.Bytes())
			dialog.ShowInformation("成功", "审计报告导出完成", myWindow)
		}, myWindow)
		d.SetFileName("Memscan_Audit_Report.txt")
		d.Show()
	})
	exportBtn.Disable()

	// 扫描按钮
	var scanBtn *widget.Button
	scanBtn = widget.NewButtonWithIcon("立即扫描", theme.SearchIcon(), func() {
		keyword := searchInput.Text
		if keyword == "" {
			dialog.ShowInformation("提示", "请输入检索关键词", myWindow)
			return
		}
		if fuzzyCheck.Checked {
			if _, err := regexp.Compile(keyword); err != nil {
				dialog.ShowError(fmt.Errorf("正则表达式无效: %v", err), myWindow)
				return
			}
		}

		processGroups = nil
		allScanResults = nil
		resultBox.Objects = []fyne.CanvasObject{widget.NewLabel("正在检索系统内存并关联网络连接信息...")}
		scanBtn.Disable()
		scanBtn.SetText("扫描中...")
		exportBtn.Disable()
		filterInput.Disable()
		resultBox.Refresh()

		go func() {
			netMap := getNetworkMap()
			tempData := scanMemoryWithNet(keyword, fuzzyCheck.Checked, caseCheck.Checked, netMap)
			time.Sleep(100 * time.Millisecond)
			allScanResults = tempData
			if len(allScanResults) > 0 {
				exportBtn.Enable()
				filterInput.Enable()
			}
			resetAndRender()
			scanBtn.Enable()
			scanBtn.SetText("立即扫描")
		}()
	})
	scanBtn.Importance = widget.HighImportance

	// 整体布局
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

// ====================== 底层Windows API函数 =======================
func getNetworkMap() map[uint32][]string {
	netMap := make(map[uint32][]string)
	var size uint32
	_, _, _ = procGetTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(AF_INET), uintptr(TCP_TABLE_OWNER_PID_ALL), 0)
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
			h, err := windows.OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, pid)
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
