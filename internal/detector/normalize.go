package detector

import (
	"strings"
	"unicode"
)

// variantFoldMap folds common Traditional Chinese and homoglyph evasion characters
// to their canonical Simplified equivalents for compact rule matching.
var variantFoldMap = map[rune]rune{
	// Common Traditional -> Simplified seen in Telegram comment spam
	'\u5152': '\u513f', // 兒 -> 儿
	'\u5b78': '\u5b66', // 學 -> 学
	'\u8996': '\u89c6', // 視 -> 视
	'\u983b': '\u9891', // 頻 -> 频
	'\u7db2': '\u7f51', // 網 -> 网
	'\u9032': '\u8fdb', // 進 -> 进
	'\u7c21': '\u7b80', // 簡 -> 简
	'\u5f37': '\u5f3a', // 強 -> 强
	'\u8655': '\u5904', // 處 -> 处
	'\u898b': '\u89c1', // 見 -> 见
	'\u6b72': '\u5c81', // 歲 -> 岁
	'\u9593': '\u95f4', // 間 -> 间
	'\u9ede': '\u70b9', // 點 -> 点
	'\u982d': '\u5934', // 頭 -> 头
	'\u9801': '\u9875', // 頁 -> 页
	'\u96b1': '\u9690', // 隱 -> 隐
	'\u8cc7': '\u8d44', // 資 -> 资
	'\u7d1a': '\u7ea7', // 級 -> 级
	'\u502b': '\u4f26', // 倫 -> 伦
	'\u4e82': '\u4e71', // 亂 -> 乱
	'\u59e6': '\u5978', // 姦 -> 奸
	'\u863f': '\u841d', // 蘿 -> 萝
	'\u8cbb': '\u8d39', // 費 -> 费
	'\u6a94': '\u6863', // 檔 -> 档
	'\u7368': '\u72ec', // 獨 -> 独
	'\u7db5': '\u7f51',
	// Kangxi Radicals -> standard CJK Unified Ideographs
	'\u2f25': '\u5973', // ⼥ -> 女
	'\u2f57': '\u7236', // ⽗ -> 父
	'\u2f09': '\u513f', // ⼉ -> 儿
	'\u2f26': '\u5b50', // ⼦ -> 子
	'\u2f29': '\u5c0f', // ⼩ -> 小
	'\u2f92': '\u89c1', // ⾒ -> 见
}

// NormalizeText strips zero-width/invisible characters and folds fullwidth ASCII to halfwidth.
func NormalizeText(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\u200b', '\u200c', '\u200d', '\u200e', '\u200f',
			'\u2060', '\ufeff', '\u00ad', '\u034f', '\u2800':
			continue
		}
		// Fullwidth ASCII variants (！..～) -> standard ASCII (!..~)
		if r >= 0xFF01 && r <= 0xFF5E {
			r = r - 0xFEE0
		} else if r == 0x3000 { // Ideographic space
			r = ' '
		}
		b.WriteRune(r)
	}
	return b.String()
}

// CompactAndFold normalizes text, folds Traditional/radical evasion variants to canonical forms,
// and strips all whitespace and punctuation separators (e.g. spaces, commas, dots, slashes)
// while preserving letters, CJK ideographs, digits, and symbol/emoji anchors (e.g. ⬅, ←, 👈, 🔞).
func CompactAndFold(s string) string {
	if s == "" {
		return ""
	}
	norm := NormalizeText(s)
	var b strings.Builder
	b.Grow(len(norm))
	for _, r := range norm {
		// Strip spaces, punctuation, control/format characters, and combining marks.
		if unicode.IsSpace(r) || unicode.IsPunct(r) || unicode.IsControl(r) ||
			unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if mapped, ok := variantFoldMap[r]; ok {
			r = mapped
		}
		b.WriteRune(r)
	}
	return b.String()
}
