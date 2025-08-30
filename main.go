package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/joho/godotenv"
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

func loadConfig() (string, string, int64) {
    err := godotenv.Load()
    if err != nil {
        log.Println("[INFO] .env файл не найден, используем переменные окружения")
    }

    token := os.Getenv("TELEGRAM_TOKEN")
    if token == "" {
        log.Fatal("[ERROR] Не задан TELEGRAM_TOKEN. Установите переменную окружения:")
        log.Fatal("export TELEGRAM_TOKEN=ваш_токен_бота")
    }

    wgInterface := os.Getenv("WG_INTERFACE")
    if wgInterface == "" {
        wgInterface = "wg0" // значение по умолчанию
    }

    allowedUserStr := os.Getenv("ALLOWED_USER")
    if allowedUserStr == "" {
        log.Fatal("[ERROR] Не задан ALLOWED_USER в .env или переменной окружения")
    }

    allowedUserInt, err := strconv.Atoi(allowedUserStr)
    if err != nil {
        log.Fatalf("[ERROR] Неверный ALLOWED_USER: %v", err)
    }

    allowedUser := int64(allowedUserInt)

    return token, wgInterface, allowedUser
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

	// Загружаем конфигурацию
	token, wgInterface, allowedUser := loadConfig()
	if logLevel == "debug" {
		debugLog.Printf("Используемый TELEGRAM_TOKEN: %s, WG_INTERFACE: %s, ALLOWED_USER: %d\n", token, wgInterface, allowedUser)
	}

	// Создание бота
	bot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		log.Fatalf("[ERROR] Ошибка при авторизации бота: %v\nПроверьте токен в TELEGRAM_TOKEN", err)
	}

	if bot.Self.UserName == "" {
		log.Fatal("[ERROR] Бот не авторизован. Проверьте токен.")
	}

	infoLog.Printf("Бот авторизован как: %s", bot.Self.UserName)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)

	// Цикл обработки сообщений
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
