package main

import (
	"flag"
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

// runCommand выполняет команду и возвращает вывод, логируя только факт выполнения в debug
func runCommand(cmd string, args ...string) (string, error) {
	out, err := exec.Command(cmd, args...).CombinedOutput()

	if logLevel == "debug" {
		debugLog.Printf("Выполнена команда: %s %s | Ошибка: %v\n",
			cmd, strings.Join(args, " "), err)
	}

	return string(out), err
}

// loadConfig читает TELEGRAM_TOKEN, WG_INTERFACE и ALLOWED_USER из .env или переменных окружения
func loadConfig() (string, string, int64) {
	_ = godotenv.Load() // если .env нет, продолжаем

	token := os.Getenv("TELEGRAM_TOKEN")
	if token == "" {
		log.Fatal("[ERROR] Не задан TELEGRAM_TOKEN. Установите переменную окружения:")
		log.Fatal("export TELEGRAM_TOKEN=ваш_токен_бота")
	}

	wgInterface := os.Getenv("WG_INTERFACE")
	if wgInterface == "" {
		wgInterface = "wg0"
	}

	allowedUserStr := os.Getenv("ALLOWED_USER")
	if allowedUserStr == "" {
		log.Fatal("[ERROR] Не задан ALLOWED_USER в .env или окружении")
	}

	allowedUserInt, err := strconv.Atoi(allowedUserStr)
	if err != nil {
		log.Fatalf("[ERROR] Неверный ALLOWED_USER: %v", err)
	}

	return token, wgInterface, int64(allowedUserInt)
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

	// Загружаем конфиг
	token, wgInterface, allowedUser := loadConfig()
	if logLevel == "debug" {
		debugLog.Printf("WG_INTERFACE: %s, ALLOWED_USER: %d\n", wgInterface, allowedUser)
		debugLog.Printf("TELEGRAM_TOKEN: %s\n", token)
	}

	// Создание бота
	bot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		log.Fatalf("[ERROR] Ошибка при авторизации бота: %v", err)
	}
	if bot.Self.UserName == "" {
		log.Fatal("[ERROR] Бот не авторизован. Проверьте токен.")
	}

	infoLog.Printf("Бот авторизован как: %s", bot.Self.UserName)

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
			out, _ := runCommand("sudo", "wg", "show")

			if len(out) > 4000 {
				out = out[:4000] + "\n...(output truncated)"
			}

			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "📊 Статус:\n"+out)
			bot.Send(msg)

			if logLevel == "info" || logLevel == "debug" {
				infoLog.Printf("Выполнена команда /status пользователем %d", userID)
			}

		case "up":
			out, _ := runCommand("sudo", "wg-quick", "up", wgInterface)
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "✅ Интерфейс поднят\n"+out)
			bot.Send(msg)
			if logLevel == "info" || logLevel == "debug" {
				infoLog.Printf("Выполнена команда /up пользователем %d", userID)
			}

		case "down":
			out, _ := runCommand("sudo", "wg-quick", "down", wgInterface)
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "⛔ Интерфейс выключен\n"+out)
			bot.Send(msg)
			if logLevel == "info" || logLevel == "debug" {
				infoLog.Printf("Выполнена команда /down пользователем %d", userID)
			}

		default:
			if strings.HasPrefix(update.Message.Text, "/") {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID,
					"Команды:\n/status — показать статус\n/up — поднять wg0\n/down — выключить wg0")
				bot.Send(msg)
				if logLevel == "debug" {
					debugLog.Printf("Неизвестная команда: %s | Пользователь: %d", cmd, userID)
				}
			}
		}
	}
}
