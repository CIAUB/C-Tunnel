// Package cli is the interactive terminal menu of ctunnel.
package cli

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"ctunnel/pkg/version"
)

const (
	Reset = "\033[0m"
	Bold  = "\033[1m"
	Red   = "\033[31m"
	White = "\033[37m"
	Gray  = "\033[90m"

	RuleWidth = 55
)

var reader = bufio.NewReader(os.Stdin)

func Clear() {
	fmt.Print("\033[2J\033[H")
}

func Logo() {
	logo := `
   ______     ______                        __
  / ____/    /_  __/_  ______  ____  ___  / /
 / /  ______  / / / / / / __ \/ __ \/ _ \/ / 
/ /__/_____/ / / / /_/ / / / / / / /  __/ /  
\____/      /_/  \__,_/_/ /_/_/ /_/\___/_/   `
	fmt.Printf("%s%s%s%s\n", Bold, Red, logo, Reset)
	fmt.Printf(" %sC-Tunnel v%s — kernel and encrypted UDP tunnels, one iran to many kharej%s\n", Gray, version.Version, Reset)
	fmt.Printf(" %sTelegram: %s%s\n\n", Gray, version.Telegram, Reset)
}

func Rule() {
	fmt.Printf(" %s%s%s\n", Gray, strings.Repeat("═", RuleWidth), Reset)
}

func Header() {
	Clear()
	Logo()
	Rule()
	fmt.Println()
}

func Title(text string) {
	fmt.Printf("\n %s%s%s%s\n", Bold, Red, strings.ToUpper(text), Reset)
	Rule()
	fmt.Println()
}

func Opt(n, title, desc string) {
	optW(n, title, desc, 18)
}

func optW(n, title, desc string, width int) {
	if desc != "" {
		fmt.Printf(" %s%2s)%s %s%-*s%s  %s%s%s\n",
			Red, n, Reset,
			Bold+White, width, title, Reset,
			Gray, desc, Reset)
	} else {
		fmt.Printf(" %s%2s)%s %s%s%s\n",
			Red, n, Reset,
			Bold+White, title, Reset)
	}
}

type MenuOpt struct {
	Title string
	Desc  string
}

func ChooseOpt(title string, opts []MenuOpt) int {
	Title(title)
	w := 18
	for _, o := range opts {
		if len(o.Title) > w {
			w = len(o.Title)
		}
	}
	for i, o := range opts {
		optW(strconv.Itoa(i+1), o.Title, o.Desc, w)
	}
	fmt.Println()
	Rule()
	raw := Ask("Enter your choice (0 to go back)", "0")
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 1 || n > len(opts) {
		return 0
	}
	return n
}

func KV(key, val string) {
	fmt.Printf("   %s%-18s%s %s%s%s\n", Gray, key, Reset, Bold+White, val, Reset)
}

func Ok(msg string) {
	fmt.Printf(" %s[OK]%s %s\n", Bold+White, Reset, msg)
}

func Warn(msg string) {
	fmt.Printf(" %s[!]%s  %s\n", Red, Reset, msg)
}

func Err(msg string) {
	fmt.Printf(" %s%s[X]  %s%s\n", Bold, Red, msg, Reset)
}

func Info(msg string) {
	fmt.Printf(" %s[*]%s  %s\n", Gray, Reset, msg)
}

func Subtle(msg string) {
	fmt.Printf("   %s%s%s\n", Gray, msg, Reset)
}

func Step(n, total int, msg string) {
	fmt.Printf("\n %s[%d/%d]%s %s%s%s\n", Red, n, total, Reset, Bold+White, msg, Reset)
}

func Pause() {
	fmt.Printf("\n %sPress Enter to continue...%s", Gray, Reset)
	_, _ = reader.ReadString('\n')
}

func Ask(prompt, def string) string {
	if def != "" {
		fmt.Printf(" %s%s%s %s[%s]%s: ", Bold+White, prompt, Reset, Gray, def, Reset)
	} else {
		fmt.Printf(" %s%s%s: ", Bold+White, prompt, Reset)
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return def
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func Confirm(prompt string, defYes bool) bool {
	hint := "y/N"
	if defYes {
		hint = "Y/n"
	}
	fmt.Printf(" %s%s%s %s[%s]%s: ", Bold+White, prompt, Reset, Gray, hint, Reset)
	line, err := reader.ReadString('\n')
	if err != nil {
		return defYes
	}
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" {
		return defYes
	}
	return line == "y" || line == "yes"
}
