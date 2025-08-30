package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

const (
	wgInterface = "wg0"          // имя интерфейса WireGuard
	allowedUser = 107719627      // ваш Telegram user ID
)

func runCommand(cmd string, args ...string) string {
	out, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Ошибка: %v\n%s", err, string(out))
	}
	return string(out)
}

func main() {
	token := os.Getenv("TELEGRAM_TOKEN")
	if token == "" {
		log.Fatal("Не задан TELEGRAM_TOKEN")
	}

	bot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		log.Fatal(err)
	}

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message == nil { // ignore non-messages
			continue
		}

		userID := update.Message.From.ID
		if userID != allowedUser {
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "⛔ Доступ запрещён")
			bot.Send(msg)
			continue
		}

		switch update.Message.Command() {
		case "status":
			out := runCommand("wg", "show")
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "📊 Статус:\n"+out)
			if len(msg.Text) > 4000 {
				msg.Text = msg.Text[:4000] + "\n...(output truncated)"
			}
			bot.Send(msg)

		case "up":
			out := runCommand("wg-quick", "up", wgInterface)
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "✅ Интерфейс поднят\n"+out)
			bot.Send(msg)

		case "down":
			out := runCommand("wg-quick", "down", wgInterface)
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "⛔ Интерфейс выключен\n"+out)
			bot.Send(msg)

		default:
			if strings.HasPrefix(update.Message.Text, "/") {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID,
					"Команды:\n/status — показать статус\n/up — поднять wg0\n/down — выключить wg0")
				bot.Send(msg)
			}
		}
	}
}