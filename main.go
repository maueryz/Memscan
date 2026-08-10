package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"image/color"
	"io/ioutil"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
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
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"
)

// ====================== 全局配置常量 =======================
const (
	// 虚拟滚动预加载缓冲区
	PRELOAD_BUFFER_LINES = 3
	// 单条折叠行固定高度
	SINGLE_COLLAPSED_LINE_HEIGHT = 50
	// 展开分页每页命中数
	HITS_PER_PAGE = 5
	// 单进程最多存储的命中条数（用于分页展示；真实命中数完整统计，不受此限）
	MAX_STORED_HITS_PER_PROCESS = 200
	// Windows API 系统常量
	TCP_TABLE_OWNER_PID_ALL   = 5
	AF_INET                   = 2
	AF_INET6                  = 23
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
	// 依次尝试常见中文字体，兼容 Windows Server 2008 等老系统。
	// 老系统可能没有微软雅黑(msyh)，但有宋体/黑体/楷体/仿宋。
	fontCandidates := []struct {
		path string
		name string
	}{
		{`C:\Windows\Fonts\msyh.ttc`, "msyh.ttc"},    // 微软雅黑（Win7 / Server2008 R2+）
		{`C:\Windows\Fonts\msyh.ttf`, "msyh.ttf"},    // 微软雅黑（Vista / Server2008 早期）
		{`C:\Windows\Fonts\simhei.ttf`, "simhei.ttf"}, // 黑体
		{`C:\Windows\Fonts\simsun.ttc`, "simsun.ttc"}, // 宋体
		{`C:\Windows\Fonts\simkai.ttf`, "simkai.ttf"}, // 楷体
		{`C:\Windows\Fonts\simfang.ttf`, "simfang.ttf"}, // 仿宋
	}
	for _, c := range fontCandidates {
		fontData, err := ioutil.ReadFile(c.path)
		if err == nil {
			chineseFontResource = &fyne.StaticResource{
				StaticName:    c.name,
				StaticContent: fontData,
			}
			return
		}
	}
	chineseFontResource = nil
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

// ====================== 老系统控制台中文输出修复 =======================
// Windows Server 2008 / XP 等老系统的控制台默认使用 GBK(936)、Big5(950) 等
// 非 UTF-8 代码页，直接输出 UTF-8 字节会被显示成乱码。
// 这里检测控制台输出代码页，把输出转码后再写 stdout；重定向到文件时保持 UTF-8。
type consoleWriter struct {
	enc *encoding.Encoder
}

func newConsoleWriter() *consoleWriter {
	if fi, err := os.Stdout.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		// 输出被重定向到文件/管道时，保持 UTF-8 原样
		return &consoleWriter{}
	}
	switch consoleOutputCP() {
	case 936:
		return &consoleWriter{enc: simplifiedchinese.GBK.NewEncoder()}
	case 950:
		return &consoleWriter{enc: traditionalchinese.Big5.NewEncoder()}
	case 932:
		return &consoleWriter{enc: japanese.ShiftJIS.NewEncoder()}
	case 949:
		return &consoleWriter{enc: korean.EUCKR.NewEncoder()}
	default:
		// 65001(UTF-8) 等其他代码页直接原样输出
		return &consoleWriter{}
	}
}

// 读取控制台当前输出代码页（如 936=GBK、950=Big5、932=Shift-JIS、949=EUC-KR、65001=UTF-8）
func consoleOutputCP() uint32 {
	cp, _, _ := procGetConsoleOutputCP.Call()
	return uint32(cp)
}

func (w *consoleWriter) Println(a ...interface{}) {
	w.Printf("%s\n", fmt.Sprint(a...))
}

func (w *consoleWriter) Print(s string) {
	if w.enc != nil {
		if out, err := w.enc.Bytes([]byte(s)); err == nil {
			os.Stdout.Write(out)
			return
		}
	}
	os.Stdout.WriteString(s)
}

func (w *consoleWriter) Printf(format string, a ...interface{}) {
	s := fmt.Sprintf(format, a...)
	if w.enc != nil {
		if out, err := w.enc.Bytes([]byte(s)); err == nil {
			os.Stdout.Write(out)
			return
		}
	}
	os.Stdout.WriteString(s)
}

// ====================== 数据结构体 =======================
type MIB_TCPROW_OWNER_PID struct {
	State, LocalAddr, LocalPort, RemoteAddr, RemotePort, OwningPid uint32
}

type MIB_TCP6ROW_OWNER_PID struct {
	LocalAddr     [16]byte
	LocalScopeId  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeId uint32
	RemotePort    uint32
	State         uint32
	OwningPid     uint32
}

type ScanHit struct {
	ProcessName string
	PID         uint32
	ExePath     string
	Before      string
	Match       string
	After       string
	Encoding    string
	TotalHits   int
	Connections []string
}

type ProcessGroup struct {
	PID               uint32
	Name              string
	Conns             []string
	Hits              []ScanHit
	TotalHits         int
	currentPage       int
	cachedFullContent *fyne.Container
	isExpanded        bool
}

// ====================== 全局变量 =======================
var (
	allScanResults                 []ScanHit
	modIphlpapi                    = syscall.NewLazyDLL("iphlpapi.dll")
	procGetTCPTable                = modIphlpapi.NewProc("GetExtendedTcpTable")
	modKernel32                    = syscall.NewLazyDLL("kernel32.dll")
	procQueryFullProcessImageNameW = modKernel32.NewProc("QueryFullProcessImageNameW")
	procGetConsoleOutputCP         = modKernel32.NewProc("GetConsoleOutputCP")
	procSetConsoleOutputCP         = modKernel32.NewProc("SetConsoleOutputCP")
	procSetConsoleCP               = modKernel32.NewProc("SetConsoleCP")
	procWideCharToMultiByte        = modKernel32.NewProc("WideCharToMultiByte")
	procMultiByteToWideChar        = modKernel32.NewProc("MultiByteToWideChar")
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

	args := os.Args[1:]
	isCLIExe := strings.Contains(strings.ToLower(filepath.Base(os.Args[0])), "cli")

	// -h / --help：任何 exe 都直接输出说明书
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		forceConsoleUTF8()
		printCLIHelp(newConsoleWriter())
		return
	}

	// 命令行模式：cli 子命令，或 CLI 版 exe 直接运行
	// 规则：不带参数 -> 说明书 + 交互模式；带关键词/选项 -> 一次性扫描
	if isCLIExe || (len(args) > 0 && args[0] == "cli") {
		forceConsoleUTF8()
		cliOut := newConsoleWriter()
		cliArgs := args
		if len(cliArgs) > 0 && cliArgs[0] == "cli" {
			cliArgs = cliArgs[1:]
		}
		if len(cliArgs) == 0 {
			// 无参数：说明书 + 交互模式
			printCLIHelp(cliOut)
			interactiveCLI(cliOut)
		} else {
			// 带关键词/选项：一次性扫描
			runCLI(cliOut, cliArgs)
		}
		return
	}

	// GUI模式初始化
	var processGroups []*ProcessGroup
	var lastScrollY float32 = 0

	myApp := app.New()
	myApp.SetIcon(resourceIcoPng)
	myApp.Settings().SetTheme(&chineseTheme{})
	myWindow := myApp.NewWindow("Memscan")
	myWindow.SetIcon(resourceIcoPng)
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

	// 扫描状态与自动重扫控制（startScan 在扫描按钮处赋值）
	var startScan func(showPrompt bool)
	var scanning bool
	var pendingRescan bool
	var hasScanned bool

	// 编码选择：默认仅 UTF-8（与最初版本一致，快且覆盖大多数场景），可按需开启其他编码
	encOptionsDisplay := make([]string, 0, len(encOptions))
	for _, o := range encOptions {
		encOptionsDisplay = append(encOptionsDisplay, o.display)
	}
	encCheckGroup := widget.NewCheckGroup(encOptionsDisplay, nil)
	encCheckGroup.SetSelected([]string{"UTF-8"})
	encBtn := widget.NewButton("编码: UTF-8", nil)
	encPop := widget.NewPopUp(encCheckGroup, myWindow.Canvas())
	encCheckGroup.OnChanged = func(sel []string) {
		if len(sel) == 0 {
			encBtn.SetText("编码: 未选择")
		} else {
			encBtn.SetText("编码: " + strings.Join(sel, ","))
		}
		// 已扫描过则自动按新编码重扫，无需手动点按钮
		if hasScanned && startScan != nil {
			startScan(false)
		}
	}
	encBtn.OnTapped = func() {
		encPop.ShowAtPosition(fyne.CurrentApp().Driver().AbsolutePositionForObject(encBtn).Add(fyne.NewPos(0, encBtn.Size().Height)))
	}
	// 正则模式只按 UTF-8 匹配，编码选择框置灰
	fuzzyCheck.OnChanged = func(checked bool) {
		if checked {
			encBtn.Disable()
		} else {
			encBtn.Enable()
		}
	}

	filterInput := widget.NewEntry()
	filterInput.SetPlaceHolder("输入进程名/PID过滤结果...")
	filterInput.Disable()

	resultBox := container.NewVBox()
	scrollArea := container.NewVScroll(resultBox)

	// ====================== 核心渲染逻辑 =======================
	var dynamicRender func()
	var resetAndRender func()
	var buildPage func(g *ProcessGroup) *fyne.Container

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
			if mergeCheck.Checked && g.TotalHits > hitCount {
				hitCount = g.TotalHits // 合并模式显示真实命中总数
			}

			// 生成单行标题
			titleContainer := buildSingleLineColorTitle(g.isExpanded, hasConn, g.PID, g.Name, hitCount, func() {
				g.isExpanded = !g.isExpanded
				if !g.isExpanded {
					// 折叠后立即释放渲染资源，避免老机器卡顿
					g.cachedFullContent = nil
					g.currentPage = 0
				}
				dynamicRender()
			})

			// 展开时按需构建当前页内容（懒加载）
			if g.isExpanded && g.cachedFullContent == nil {
				g.cachedFullContent = buildPage(g)
			}

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

	buildPage = func(g *ProcessGroup) *fyne.Container {
		totalPages := (len(g.Hits) + HITS_PER_PAGE - 1) / HITS_PER_PAGE
		if totalPages < 1 {
			totalPages = 1
		}
		if g.currentPage >= totalPages {
			g.currentPage = totalPages - 1
		}
		page := g.currentPage

		box := container.NewVBox()

		// 进程路径
		if len(g.Hits) > 0 && g.Hits[0].ExePath != "" {
			pathEntry := widget.NewEntry()
			pathEntry.SetText("进程路径： " + g.Hits[0].ExePath)
			box.Add(pathEntry)
			box.Add(widget.NewSeparator())
		}

		// 当前页命中
		start := page * HITS_PER_PAGE
		end := start + HITS_PER_PAGE
		if end > len(g.Hits) {
			end = len(g.Hits)
		}
		for i := start; i < end; i++ {
			hit := g.Hits[i]
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
			copyBtn.Importance = widget.LowImportance
			hitRow := container.NewBorder(nil, nil, nil, copyBtn, rt)
			box.Add(hitRow)
			if i < end-1 {
				box.Add(widget.NewSeparator())
			}
		}

		// 命中过多提示（真实命中数超过存储上限时）
		if len(g.Hits) < g.TotalHits {
			box.Add(widget.NewLabelWithStyle(fmt.Sprintf("命中过多，仅展示前 %d 条（真实共 %d 条）", len(g.Hits), g.TotalHits), fyne.TextAlignCenter, fyne.TextStyle{Italic: true}))
		}

		// 分页控件
		prevBtn := widget.NewButtonWithIcon("上一页", theme.NavigateBackIcon(), func() {
			if g.currentPage > 0 {
				g.currentPage--
				g.cachedFullContent = nil // 翻页即释放当前页资源
				dynamicRender()
			}
		})
		nextBtn := widget.NewButtonWithIcon("下一页", theme.NavigateNextIcon(), func() {
			if g.currentPage < totalPages-1 {
				g.currentPage++
				g.cachedFullContent = nil
				dynamicRender()
			}
		})
		// 浅色按钮，与命中内容区区分开
		prevBtn.Importance = widget.MediumImportance
		nextBtn.Importance = widget.MediumImportance
		if page <= 0 {
			prevBtn.Disable()
		}
		if page >= totalPages-1 {
			nextBtn.Disable()
		}
		pageLabel := widget.NewLabel(fmt.Sprintf("第 %d/%d 页", page+1, totalPages))
		navRow := container.NewHBox(prevBtn, layout.NewSpacer(), pageLabel, layout.NewSpacer(), nextBtn)

		// 浅色底条，形成独立的分页区，视觉上更现代
		navBg := canvas.NewRectangle(theme.HoverColor())
		navBar := container.NewMax(navBg, container.NewPadded(navRow))
		box.Add(widget.NewSeparator())
		box.Add(navBar)
		return box
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
					TotalHits:         h.TotalHits,
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
					TotalHits:         h.TotalHits,
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
	// 过滤按钮：无键盘时用鼠标点击即可生效（回车仍可用）
	filterBtn := widget.NewButton("过滤", nil)
	filterBtn.Importance = widget.MediumImportance // 浅灰色
	filterBtn.Disable()
	filterBtn.OnTapped = func() { resetAndRender() }

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
				b.WriteString(fmt.Sprintf("[进程名] %s\n[PID] %d\n[路径] %s\n[命中总数] %d\n",
					h.ProcessName, h.PID, h.ExePath, h.TotalHits))
				if len(h.Connections) > 0 {
					b.WriteString("[外联地址]\n")
					for _, c := range h.Connections {
						b.WriteString("  " + c + "\n")
					}
				}
				b.WriteString(fmt.Sprintf("[编码] %s\n[匹配上下文] ...%s%s%s...\n\n",
					h.Encoding, h.Before, h.Match, h.After))
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
	startScan = func(showPrompt bool) {
		keyword := searchInput.Text
		if keyword == "" {
			if showPrompt {
				dialog.ShowInformation("提示", "请输入检索关键词", myWindow)
			}
			return
		}
		if fuzzyCheck.Checked {
			if _, err := regexp.Compile(keyword); err != nil {
				dialog.ShowError(fmt.Errorf("正则表达式无效: %v", err), myWindow)
				return
			}
		}
		if scanning {
			// 扫描进行中：记下待重扫，完成后自动补一次
			pendingRescan = true
			return
		}
		scanning = true

		processGroups = nil
		allScanResults = nil
		resultBox.Objects = []fyne.CanvasObject{widget.NewLabel("正在检索系统内存并关联网络连接信息...")}
		scanBtn.Disable()
		scanBtn.SetText("扫描中...")
		exportBtn.Disable()
		filterInput.Disable()
		filterBtn.Disable()
		resultBox.Refresh()

		go func() {
			encNames := make([]string, 0, len(encCheckGroup.Selected))
			for _, d := range encCheckGroup.Selected {
				for _, o := range encOptions {
					if o.display == d {
						encNames = append(encNames, o.name)
					}
				}
			}
			netMap := getNetworkMap()
			tempData := scanMemoryWithNet(keyword, fuzzyCheck.Checked, caseCheck.Checked, netMap, encNames)
			time.Sleep(100 * time.Millisecond)
			allScanResults = tempData
			if len(allScanResults) > 0 {
				exportBtn.Enable()
				filterInput.Enable()
				filterBtn.Enable()
			}
			resetAndRender()
			scanBtn.Enable()
			scanBtn.SetText("立即扫描")
			scanning = false
			hasScanned = true
			if pendingRescan {
				pendingRescan = false
				startScan(false)
			}
		}()
	}
	scanBtn = widget.NewButtonWithIcon("立即扫描", theme.SearchIcon(), func() { startScan(true) })
	scanBtn.Importance = widget.HighImportance

	// 整体布局
	topArea := container.NewVBox(
		widget.NewLabelWithStyle("内存检索工具", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		searchInput,
		container.NewHBox(fuzzyCheck, caseCheck, mergeCheck, onlyNetCheck, layout.NewSpacer(), scanBtn, exportBtn),
		widget.NewSeparator(),
		container.NewBorder(nil, nil, widget.NewLabel("结果过滤:"), container.NewHBox(filterBtn, encBtn), filterInput),
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
			lIP := make(net.IP, 4)
			binary.LittleEndian.PutUint32(lIP, row.LocalAddr)
			rIP := make(net.IP, 4)
			binary.LittleEndian.PutUint32(rIP, row.RemoteAddr)
			netMap[row.OwningPid] = append(netMap[row.OwningPid], fmt.Sprintf("%s -> %s",
				formatConnAddr(lIP, swapPort(row.LocalPort)),
				formatConnAddr(rIP, swapPort(row.RemotePort))))
		}
	}

	// IPv6 TCP 外联连接：微信等很多程序走 IPv6，只查 IPv4 会漏
	var size6 uint32
	_, _, _ = procGetTCPTable.Call(0, uintptr(unsafe.Pointer(&size6)), 0, uintptr(AF_INET6), uintptr(TCP_TABLE_OWNER_PID_ALL), 0)
	if size6 == 0 {
		return netMap
	}
	buffer6 := make([]byte, size6)
	ret6, _, _ := procGetTCPTable.Call(uintptr(unsafe.Pointer(&buffer6[0])), uintptr(unsafe.Pointer(&size6)), 0, uintptr(AF_INET6), uintptr(TCP_TABLE_OWNER_PID_ALL), 0)
	if ret6 != 0 {
		return netMap
	}
	numEntries6 := binary.LittleEndian.Uint32(buffer6[0:4])
	entrySize6 := int(unsafe.Sizeof(MIB_TCP6ROW_OWNER_PID{}))
	for i := 0; i < int(numEntries6); i++ {
		offset := 4 + i*entrySize6
		if offset+entrySize6 > len(buffer6) {
			break
		}
		row := (*MIB_TCP6ROW_OWNER_PID)(unsafe.Pointer(&buffer6[offset]))
		if !isZeroIPv6(row.RemoteAddr) {
			lIP := net.IP(row.LocalAddr[:])
			rIP := net.IP(row.RemoteAddr[:])
			netMap[row.OwningPid] = append(netMap[row.OwningPid], fmt.Sprintf("%s -> %s",
				formatConnAddr(lIP, swapPort(row.LocalPort)),
				formatConnAddr(rIP, swapPort(row.RemotePort))))
		}
	}
	return netMap
}

// 端口在网络字节序中高低字节互换
func swapPort(p uint32) uint32 {
	return ((p & 0xff00) >> 8) | ((p & 0x00ff) << 8)
}

// 外联地址显示格式：IPv4 不带括号，IPv6 带 []
func formatConnAddr(ip net.IP, port uint32) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%s:%d", v4.String(), port)
	}
	return fmt.Sprintf("[%s]:%d", ip.String(), port)
}

func isZeroIPv6(addr [16]byte) bool {
	for _, b := range addr {
		if b != 0 {
			return false
		}
	}
	return true
}

func getProcessPath(h windows.Handle) string {
	var buf [520]uint16
	bufLen := uint32(len(buf))
	ret, _, _ := procQueryFullProcessImageNameW.Call(
		uintptr(h), 0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufLen)),
	)
	if ret != 0 {
		return syscall.UTF16ToString(buf[:bufLen])
	}
	return ""
}

func scanMemoryWithNet(keyword string, isFuzzy, isCase bool, netMap map[uint32][]string, enabled []string) []ScanHit {
	var results []ScanHit
	if len(keyword) == 0 {
		return nil
	}
	var patterns []searchPattern
	var regex *regexp.Regexp
	if isFuzzy {
		prefix := ""
		if !isCase {
			prefix = "(?i)"
		}
		regex, _ = regexp.Compile(prefix + keyword)
	} else {
		patterns = buildSearchPatterns(keyword, isCase, enabled)
		if len(patterns) == 0 {
			return nil
		}
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
				hits := searchInProcess(h, exe, pid, patterns, regex, isFuzzy, isCase)
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

// ====================== 多编码搜索支持 =======================
const (
	CP_GBK              = 936
	CP_BIG5             = 950
	CP_SHIFTJIS         = 932
	WC_ERR_INVALID_CHARS = 0x80

	foldNone  = 0 // 不折叠（关键词无 ASCII 字母或区分大小写）
	foldASCII = 1 // UTF-8 等 ASCII 兼容编码
	foldU16LE = 2 // UTF-16LE
	foldU16BE = 3 // UTF-16BE
	foldGBK   = 4 // GBK（双字节尾字节不折叠）
	foldBIG5  = 5 // Big5
	foldSJIS  = 6 // Shift-JIS
)

type searchPattern struct {
	encName  string              // 编码名称
	pattern  []byte              // 用于查找的字节模式（已按需折叠大小写）
	needFold int                 // 内存块折叠方式（foldNone 表示不折叠）
	align    int                 // 上下文边界对齐：0=不对齐 1=UTF-8 2=UTF-16
	decode   func([]byte) string // 按编码解码上下文
}

// 界面可选编码（显示名 -> 内部名）
var encOptions = []struct {
	display string
	name    string
}{
	{"UTF-8", "utf-8"},
	{"UTF-16LE", "utf-16le"},
	{"UTF-16BE", "utf-16be"},
	{"GBK", "gbk"},
	{"Big5", "big5"},
	{"Shift-JIS", "shift-jis"},
}

// CLI 编码参数解析；"all" 返回 nil 表示全部编码
func parseEncArg(s string) ([]string, bool) {
	lower := strings.ToLower(strings.ReplaceAll(s, "，", ","))
	if lower == "all" || lower == "全部" {
		return nil, true
	}
	var out []string
	for _, part := range strings.Split(lower, ",") {
		part = strings.TrimSpace(part)
		switch part {
		case "utf8", "utf-8":
			out = append(out, "utf-8")
		case "utf16le", "utf-16le":
			out = append(out, "utf-16le")
		case "utf16be", "utf-16be":
			out = append(out, "utf-16be")
		case "gbk", "gb2312", "gb18030":
			out = append(out, "gbk")
		case "big5":
			out = append(out, "big5")
		case "shiftjis", "shift-jis", "sjis":
			out = append(out, "shift-jis")
		default:
			return nil, false
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// CLI 说明书：参数与支持的编码
func printCLIHelp(cliOut *consoleWriter) {
	cliOut.Println("Memscan 命令行模式 - 使用说明")
	cliOut.Println("==================================")
	cliOut.Println("启动方式:")
	cliOut.Println("  Memscan.exe cli                  无参数：说明书 + 交互模式")
	cliOut.Println("  Memscan_CLI.exe                  同上（命令行版直接双击也可）")
	cliOut.Println("  Memscan.exe cli <关键词> [选项]   一次性扫描")
	cliOut.Println("  Memscan_CLI.exe -h               仅显示本说明")
	cliOut.Println()
	cliOut.Println("选项:")
	cliOut.Println("  -a            全量扫描（全部编码）")
	cliOut.Println("  -case         区分大小写")
	cliOut.Println("  -regex        正则匹配（仅 UTF-8）")
	cliOut.Println("  -net          仅显示有外联连接的进程")
	cliOut.Println("  -list         紧凑列表模式（一行一个进程）")
	cliOut.Println("  -enc <列表>   指定搜索编码，逗号分隔（默认 utf8；all=全部）")
	cliOut.Println("  -max <N>      最多输出 N 条命中（-list 下为进程数）")
	cliOut.Println("  -h, --help    显示本说明")
	cliOut.Println()
	cliOut.Println("支持的编码:")
	cliOut.Println("  utf-8        UTF-8（默认，覆盖绝大多数场景）")
	cliOut.Println("  utf-16le     UTF-16 小端（Windows 原生程序、微信等）")
	cliOut.Println("  utf-16be     UTF-16 大端（仅关键词含非 ASCII 字符时生效）")
	cliOut.Println("  gbk          GBK / GB2312（老国产软件）")
	cliOut.Println("  big5         Big5（繁体中文软件）")
	cliOut.Println("  shift-jis    Shift-JIS（日文软件）")
	cliOut.Println()
	cliOut.Println("示例:")
	cliOut.Println("  Memscan_CLI.exe cli \"weixin.qq.com\"")
	cliOut.Println("  Memscan_CLI.exe cli \"微信\" -a")
	cliOut.Println("  Memscan_CLI.exe cli \"https\" -list -max 20")
	cliOut.Println("  Memscan_CLI.exe cli \"メール\" -enc utf16le,shift-jis")
}

// 强制控制台输出/输入代码页为 UTF-8，避免中文乱码（老系统的 GBK 转码仍作为输出兜底）
func forceConsoleUTF8() {
	procSetConsoleOutputCP.Call(uintptr(65001))
	procSetConsoleCP.Call(uintptr(65001))
}

// 执行一次 CLI 扫描（args 为 cli 之后的参数，如 ["微信", "-a"]）
func runCLI(cliOut *consoleWriter, args []string) int {
	keyword := ""
	encSel := []string{"utf-8"}
	isCase := false
	isFuzzy := false
	onlyNet := false
	listMode := false
	maxOut := 0
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-a":
			encSel = nil
		case a == "-h" || a == "--help":
			printCLIHelp(cliOut)
			return 1
		case a == "-case":
			isCase = true
		case a == "-regex":
			isFuzzy = true
		case a == "-net":
			onlyNet = true
		case a == "-list":
			listMode = true
		case a == "-enc" && i+1 < len(args):
			i++
			parsed, ok := parseEncArg(args[i])
			if !ok {
				cliOut.Println("[!] 编码参数无效，使用默认: utf8")
			} else {
				encSel = parsed
			}
		case a == "-max" && i+1 < len(args):
			i++
			if n, err := strconv.Atoi(args[i]); err == nil && n > 0 {
				maxOut = n
			}
		case keyword == "" && !strings.HasPrefix(a, "-"):
			keyword = a
		default:
			cliOut.Println("[!] 未知参数: " + a)
			printCLIHelp(cliOut)
			return 1
		}
	}
	if keyword == "" {
		printCLIHelp(cliOut)
		return 1
	}
	if isFuzzy {
		if _, err := regexp.Compile(keyword); err != nil {
			cliOut.Println("[!] 正则表达式无效: " + err.Error())
			return 1
		}
	}

	encDesc := strings.Join(encSel, ",")
	if encSel == nil {
		encDesc = "全部"
	}
	cliOut.Println("==================================")
	cliOut.Println("Memscan 命令行模式")
	cliOut.Println("扫描关键词：", keyword)
	cliOut.Println("扫描编码：", encDesc)
	cliOut.Println("==================================")

	netMap := getNetworkMap()
	results := scanMemoryWithNet(keyword, isFuzzy, isCase, netMap, encSel)

	filtered := results
	if onlyNet {
		filtered = nil
		for _, h := range results {
			if len(h.Connections) > 0 {
				filtered = append(filtered, h)
			}
		}
	}

	if len(filtered) == 0 {
		cliOut.Println("[+] 未扫描到匹配结果")
		return 1
	}

	procSet := make(map[uint32]bool)
	for _, h := range filtered {
		procSet[h.PID] = true
	}

	printed := 0
	if listMode {
		type procStat struct {
			name  string
			pid   uint32
			count int
			net   bool
		}
		seen := make(map[uint32]*procStat)
		var order []uint32
		for _, h := range filtered {
			s, ok := seen[h.PID]
			if !ok {
				s = &procStat{name: h.ProcessName, pid: h.PID}
				seen[h.PID] = s
				order = append(order, h.PID)
			}
			s.count = h.TotalHits // 显示真实命中总数
			if len(h.Connections) > 0 {
				s.net = true
			}
		}
		for _, pid := range order {
			if maxOut > 0 && printed >= maxOut {
				break
			}
			s := seen[pid]
			netFlag := ""
			if s.net {
				netFlag = "  <!> 有外联"
			}
			cliOut.Printf("[进程] %s (PID %d) 命中 %d 条%s\n", s.name, s.pid, s.count, netFlag)
			printed++
		}
	} else {
		for _, hit := range filtered {
			if maxOut > 0 && printed >= maxOut {
				break
			}
			cliOut.Printf("\n[进程名] %s\n[PID] %d\n", hit.ProcessName, hit.PID)
			if hit.ExePath != "" {
				cliOut.Printf("[路径] %s\n", hit.ExePath)
			}
			if len(hit.Connections) > 0 {
				cliOut.Printf("[外联地址]\n")
				for _, c := range hit.Connections {
					cliOut.Printf("  %s\n", c)
				}
			}
			cliOut.Printf("[编码] %s\n", hit.Encoding)
			cliOut.Printf("[匹配上下文] ...%s%s%s...\n", hit.Before, hit.Match, hit.After)
			printed++
		}
	}

	realTotal := 0
	pidTotal := make(map[uint32]int)
	for _, h := range filtered {
		if _, ok := pidTotal[h.PID]; !ok {
			pidTotal[h.PID] = h.TotalHits
		}
	}
	for _, t := range pidTotal {
		realTotal += t
	}
	cliOut.Printf("\n[+] 共 %d 个进程，%d 条命中", len(procSet), realTotal)
	if maxOut > 0 && printed >= maxOut && printed < len(filtered) {
		cliOut.Printf("（仅显示前 %d 条）", printed)
	}
	cliOut.Println()
	return 0
}

// 双击启动时的交互模式：可持续输入关键词反复扫描
func interactiveCLI(cliOut *consoleWriter) {
	cliOut.Println()
	cliOut.Println("已进入交互模式：输入关键词开始扫描，输入 help 查看说明，输入 exit 退出")
	reader := bufio.NewReader(os.Stdin)
	for {
		cliOut.Print("Memscan> ")
		line, err := reader.ReadString('\n')
		if err != nil {
			break // 输入结束（EOF）时退出
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch strings.ToLower(line) {
		case "exit", "quit", "q":
			return
		case "help", "h", "?":
			printCLIHelp(cliOut)
			continue
		}
		runCLI(cliOut, splitArgs(line))
	}
}

// 按引号感知地拆分一行命令（支持 "关键词 带空格" 和参数）
func splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuote = !inQuote
		case (c == ' ' || c == '\t') && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// 生成关键词在所选编码下的字节模式
// enabled 为 nil 表示全部编码（CLI 默认），空列表表示一个都不选
func buildSearchPatterns(keyword string, isCase bool, enabled []string) []searchPattern {
	want := func(name string) bool {
		if enabled == nil {
			return true
		}
		for _, e := range enabled {
			if e == name {
				return true
			}
		}
		return false
	}
	var patterns []searchPattern
	add := func(name string, raw []byte, align int, decode func([]byte) string, foldType int) {
		if len(raw) == 0 {
			return
		}
		p := searchPattern{encName: name, pattern: raw, align: align, decode: decode}
		if !isCase && hasASCIILetters(raw) {
			p.needFold = foldType
			p.pattern = foldByType(raw, foldType)
		}
		patterns = append(patterns, p)
	}

	if want("utf-8") {
		add("utf-8", []byte(keyword), 1, decodeUTF8, foldASCII)
	}

	if runes := []rune(keyword); len(runes) > 0 {
		u16 := utf16.Encode(runes)
		le := make([]byte, len(u16)*2)
		be := make([]byte, len(u16)*2)
		for i, r := range u16 {
			binary.LittleEndian.PutUint16(le[i*2:], r)
			binary.BigEndian.PutUint16(be[i*2:], r)
		}
		if want("utf-16le") {
			add("utf-16le", le, 2, decodeUTF16LE, foldU16LE)
		}
		// 纯 ASCII 关键词跳过 UTF-16BE：其模式会与 UTF-16LE 文本错位一字节假匹配
		// （产生乱码命中）；含中文等非 ASCII 字符时 BE 模式是真实的，需要保留
		if hasNonASCII(keyword) && want("utf-16be") {
			add("utf-16be", be, 2, decodeUTF16BE, foldU16BE)
		}
	}

	codePages := []struct {
		name    string
		cp      uint32
		foldTyp int
	}{
		{"gbk", CP_GBK, foldGBK},
		{"big5", CP_BIG5, foldBIG5},
		{"shift-jis", CP_SHIFTJIS, foldSJIS},
	}
	for _, c := range codePages {
		name, cp, foldTyp := c.name, c.cp, c.foldTyp
		if want(name) {
			if b, ok := encodeToCodePage(cp, keyword); ok {
				add(name, b, 0, func(d []byte) string { return decodeCodePage(cp, d) }, foldTyp)
			}
		}
	}
	return patterns
}

func hasASCIILetters(b []byte) bool {
	for _, c := range b {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			return true
		}
	}
	return false
}

func hasNonASCII(s string) bool {
	for _, r := range s {
		if r > 0x7F {
			return true
		}
	}
	return false
}

// 按编码折叠大小写（模式与内存块共用同一规则，保证字节偏移一致）
func foldByType(d []byte, foldType int) []byte {
	switch foldType {
	case foldU16LE:
		return toLowerASCII16LE(d)
	case foldU16BE:
		return toLowerASCII16BE(d)
	case foldGBK:
		return toLowerASCIIWithTrail(d, isGBKLead)
	case foldBIG5:
		return toLowerASCIIWithTrail(d, isBIG5Lead)
	case foldSJIS:
		return toLowerASCIIWithTrail(d, isSJISLead)
	case foldASCII:
		return toLowerASCII(d)
	}
	return d
}

func isGBKLead(b byte) bool  { return b >= 0x81 }
func isBIG5Lead(b byte) bool { return b >= 0x81 }
func isSJISLead(b byte) bool { return (b >= 0x81 && b <= 0x9F) || (b >= 0xE0 && b <= 0xFC) }

// UTF-16LE 折叠：仅折叠与 0x00 配对的 ASCII 字节，避免破坏多字节字符
func toLowerASCII16LE(d []byte) []byte {
	r := make([]byte, len(d))
	copy(r, d)
	for i := 0; i+1 < len(d); i += 2 {
		if d[i+1] == 0 && d[i] >= 'A' && d[i] <= 'Z' {
			r[i] = d[i] + 32
		}
	}
	return r
}

// UTF-16BE 折叠：仅折叠与 0x00 配对的 ASCII 字节
func toLowerASCII16BE(d []byte) []byte {
	r := make([]byte, len(d))
	copy(r, d)
	for i := 0; i+1 < len(d); i += 2 {
		if d[i] == 0 && d[i+1] >= 'A' && d[i+1] <= 'Z' {
			r[i+1] = d[i+1] + 32
		}
	}
	return r
}

// 双字节编码折叠：跳过尾字节，避免破坏汉字
func toLowerASCIIWithTrail(d []byte, isLead func(byte) bool) []byte {
	r := make([]byte, len(d))
	for i := 0; i < len(d); {
		b := d[i]
		if isLead(b) && i+1 < len(d) {
			r[i] = b
			r[i+1] = d[i+1]
			i += 2
			continue
		}
		if b >= 'A' && b <= 'Z' {
			r[i] = b + 32
		} else {
			r[i] = b
		}
		i++
	}
	return r
}

// 将关键词编码为指定代码页字节（含无法编码的字符则返回 false 跳过该编码）
func encodeToCodePage(cp uint32, s string) ([]byte, bool) {
	u16 := utf16.Encode([]rune(s))
	if len(u16) == 0 {
		return nil, false
	}
	flags := uintptr(WC_ERR_INVALID_CHARS)
	r1, _, _ := procWideCharToMultiByte.Call(
		uintptr(cp), flags,
		uintptr(unsafe.Pointer(&u16[0])), uintptr(len(u16)),
		0, 0, 0, 0)
	n := int(r1)
	if n <= 0 {
		return nil, false
	}
	buf := make([]byte, n)
	r2, _, _ := procWideCharToMultiByte.Call(
		uintptr(cp), flags,
		uintptr(unsafe.Pointer(&u16[0])), uintptr(len(u16)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(n), 0, 0)
	if int(r2) == 0 {
		return nil, false
	}
	return buf, true
}

// 将代码页字节解码为可读文本（非法字节由系统替换为 '?'）
func decodeCodePage(cp uint32, d []byte) string {
	if len(d) == 0 {
		return ""
	}
	r1, _, _ := procMultiByteToWideChar.Call(
		uintptr(cp), 0,
		uintptr(unsafe.Pointer(&d[0])), uintptr(len(d)),
		0, 0)
	n := int(r1)
	if n <= 0 {
		return strings.Repeat(".", len(d))
	}
	buf := make([]uint16, n)
	r2, _, _ := procMultiByteToWideChar.Call(
		uintptr(cp), 0,
		uintptr(unsafe.Pointer(&d[0])), uintptr(len(d)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(n))
	if int(r2) == 0 {
		return strings.Repeat(".", len(d))
	}
	return sanitizeRunes(utf16.Decode(buf))
}

func searchInProcess(h windows.Handle, exe string, pid uint32, patterns []searchPattern, reg *regexp.Regexp, isFuzzy, isCase bool) []ScanHit {
	var hits []ScanHit
	totalHits := 0 // 真实命中总数（不受存储上限影响）
	var exePath string
	var pathFetched bool
	var addr uintptr
	var mem windows.MemoryBasicInformation
	for {
		if err := windows.VirtualQueryEx(h, addr, &mem, unsafe.Sizeof(mem)); err != nil {
			break
		}
		if mem.State == MEM_COMMIT && mem.RegionSize < MAX_MEMORY_REGION_SIZE && (mem.Protect == PAGE_READWRITE || mem.Protect == PAGE_EXECUTE_READWRITE) {
			buf := make([]byte, mem.RegionSize)
			var n uintptr
			if err := windows.ReadProcessMemory(h, addr, &buf[0], mem.RegionSize, &n); err == nil && n > 0 {
				chunk := buf[:n]
				offset := 0
				var foldedChunks [7][]byte
				for {
					// 正则模式：仅按 UTF-8 匹配
					if isFuzzy && reg != nil {
						loc := reg.FindIndex(chunk[offset:])
						if loc == nil {
							break
						}
						start, end := offset+loc[0], offset+loc[1]
						totalHits++
						if len(hits) < MAX_STORED_HITS_PER_PROCESS {
							if !pathFetched {
								exePath = getProcessPath(h)
								pathFetched = true
							}
							b, m, a := extractCtxEnc(chunk, start, end, decodeUTF8, 1)
							hits = append(hits, ScanHit{ProcessName: exe, PID: pid, ExePath: exePath, Before: b, Match: m, After: a, Encoding: "utf-8"})
						}
						offset = end
						continue
					}

					// 多编码：取所有编码中最靠前的命中
					bestStart, bestEnd, bestP := -1, -1, -1
					for pi := range patterns {
						p := &patterns[pi]
						hay := chunk
						if p.needFold != 0 {
							if foldedChunks[p.needFold] == nil {
								foldedChunks[p.needFold] = foldByType(chunk, p.needFold)
							}
							hay = foldedChunks[p.needFold]
						}
						idx := bytes.Index(hay[offset:], p.pattern)
						if idx == -1 {
							continue
						}
						st, en := offset+idx, offset+idx+len(p.pattern)
						if bestStart == -1 || st < bestStart {
							bestStart, bestEnd, bestP = st, en, pi
						}
					}
					if bestStart == -1 {
						break
					}
					totalHits++
					if len(hits) < MAX_STORED_HITS_PER_PROCESS {
						p := patterns[bestP]
						if !pathFetched {
							exePath = getProcessPath(h)
							pathFetched = true
						}
						b, m, a := extractCtxEnc(chunk, bestStart, bestEnd, p.decode, p.align)
						hits = append(hits, ScanHit{ProcessName: exe, PID: pid, ExePath: exePath, Before: b, Match: m, After: a, Encoding: p.encName})
					}
					offset = bestEnd
				}
			}
		}
		oldAddr := addr
		addr += uintptr(mem.RegionSize)
		if addr <= oldAddr {
			break
		}
	}
	for i := range hits {
		hits[i].TotalHits = totalHits
	}
	return hits
}

// 按命中编码提取上下文（窗口固定 64 字节，边界按编码对齐）
func extractCtxEnc(c []byte, s, e int, decode func([]byte) string, align int) (string, string, string) {
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
	if align == 2 {
		// UTF-16：窗口边界与匹配位置保持同奇偶，避免截出半个字符
		for s1 > 0 && (s1%2) != (s%2) {
			s1--
		}
		for e1 < len(c) && (e1%2) != (e%2) {
			e1++
		}
	} else if align == 1 {
		// UTF-8：对齐到完整字符边界
		s1 = alignRuneStart(c, s1)
		e1 = alignRuneEnd(c, e1)
	}
	return decode(c[s1:s]), decode(c[s:e]), decode(c[e:e1])
}

// 向前回退到完整 UTF-8 字符的起始字节
func alignRuneStart(c []byte, pos int) int {
	if pos >= len(c) {
		return len(c)
	}
	for pos > 0 && (c[pos]&0xC0) == 0x80 {
		pos--
	}
	return pos
}

// 向前推进到完整 UTF-8 字符结束位置之后（不跨字符截断）
func alignRuneEnd(c []byte, pos int) int {
	if pos >= len(c) {
		return len(c)
	}
	if pos > 0 && (c[pos]&0xC0) == 0x80 {
		pos = alignRuneStart(c, pos)
	}
	if pos >= len(c) {
		return len(c)
	}
	_, size := utf8.DecodeRune(c[pos:])
	if size <= 0 || pos+size > len(c) {
		return len(c)
	}
	return pos + size
}

// UTF-8 解码为可读文本：保留可打印字符（含中文等），非法/不可打印字节显示为 '.'
func decodeUTF8(d []byte) string {
	var b strings.Builder
	b.Grow(len(d))
	for i := 0; i < len(d); {
		r, size := utf8.DecodeRune(d[i:])
		if r == utf8.RuneError && size <= 1 {
			// 非法字节（真正的二进制数据）→ '.'
			b.WriteByte('.')
			i++
			continue
		}
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('.')
		}
		i += size
	}
	return b.String()
}

func toUint16(d []byte, bigEndian bool) []uint16 {
	n := len(d) / 2
	u := make([]uint16, n)
	for i := 0; i < n; i++ {
		if bigEndian {
			u[i] = binary.BigEndian.Uint16(d[i*2:])
		} else {
			u[i] = binary.LittleEndian.Uint16(d[i*2:])
		}
	}
	return u
}

func decodeUTF16LE(d []byte) string { return sanitizeRunes(utf16.Decode(toUint16(d, false))) }
func decodeUTF16BE(d []byte) string { return sanitizeRunes(utf16.Decode(toUint16(d, true))) }

// 保留可打印字符，其余显示为 '.'
func sanitizeRunes(rs []rune) string {
	var b strings.Builder
	for _, r := range rs {
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('.')
		}
	}
	return b.String()
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
