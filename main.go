package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

const (
	wgInterface = "wg0"       // имя интерфейса WireGuard
	allowedUser = 123456789   // ваш Telegram user ID
)

var (
	logLevel string
	infoLog  *log.Logger
	debugLog *log.Logger
)

// runCommand выполняет системную команду и возвращает вывод
func runCommand(cmd string, args ...string) string {
	out, err := exec.Command(cmd, args...).CombinedOutput()
	if logLevel == "debug" {
		debugLog.Printf("Выполнена команда: %s %s\nВывод: %s\nОшибка: %v\n", cmd, strings.Join(args, " "), string(out), err)
	}
	if err != nil {
		return fmt.Sprintf("Ошибка: %v\n%s", err, string(out))
	}
	return string(out)
}

func main() {
	// Чтение ключей командной строки
	v := flag.Bool("v", false, "уровень info")
	vv := flag.Bool("vv", false, "уровень debug")
	flag.Parse()

	// Настройка логирования
	if *vv {
		logLevel = "debug"
	} else if *v {
		logLevel = "info"
	} else {
		logLevel = "none"
	}

	infoLog = log.New(os.Stdout, "[INFO] ", log.LstdFlags)
	debugLog = log.New(os.Stdout, "[DEBUG] ", log.LstdFlags)

	infoLog.Println("Запуск бота...")

	token := os.Getenv("TELEGRAM_TOKEN")
	if token == "" {
		log.Fatal("Не задан TELEGRAM_TOKEN")
	}

	bot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		log.Fatal(err)
	}

	infoLog.Printf("Бот авторизован как: %s\n", bot.Self.UserName)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message == nil {
			continue
		}

		userID := update.Message.From.ID
		if userID != allowedUser {
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "⛔ Доступ запрещён")
			bot.Send(msg)
			continue
		}

		cmd := update.Message.Command()
		switch cmd {
		case "status":
			out := runCommand("wg", "show")
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "📊 Статус:\n"+out)
			if len(msg.Text) > 4000 {
				msg.Text = msg.Text[:4000] + "\n...(output truncated)"
			}
			bot.Send(msg)
			if logLevel == "info" || logLevel == "debug" {
				infoLog.Println("Выполнена команда /status")
			}

		case "up":
			out := runCommand("wg-quick", "up", wgInterface)
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "✅ Интерфейс поднят\n"+out)
			bot.Send(msg)
			if logLevel == "info" || logLevel == "debug" {
				infoLog.Println("Выполнена команда /up")
			}

		case "down":
			out := runCommand("wg-quick", "down", wgInterface)
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "⛔ Интерфейс выключен\n"+out)
			bot.Send(msg)
			if logLevel == "info" || logLevel == "debug" {
				infoLog.Println("Выполнена команда /down")
			}

		default:
			if strings.HasPrefix(update.Message.Text, "/") {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID,
					"Команды:\n/status — показать статус\n/up — поднять wg0\n/down — выключить wg0")
				bot.Send(msg)
				if logLevel == "debug" {
					debugLog.Printf("Неизвестная команда: %s\n", cmd)
				}
			}
		}
	}
}
