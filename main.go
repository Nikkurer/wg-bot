package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/joho/godotenv"
)

// Config структура
type Config struct {
	TelegramToken string
	WgInterface   string
	AllowedUser   int64
}

// глобальные логгеры
var (
	infoLog  *log.Logger
	debugLog *log.Logger
	logLevel string
)

// загрузка конфига
func loadConfig() (*Config, error) {
	err := godotenv.Load()
	if err != nil {
		return nil, fmt.Errorf("ошибка загрузки .env: %v", err)
	}

	allowedUser, err := strconv.ParseInt(os.Getenv("ALLOWED_USER"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга ALLOWED_USER: %v", err)
	}

	return &Config{
		TelegramToken: os.Getenv("TELEGRAM_TOKEN"),
		WgInterface:   os.Getenv("WG_INTERFACE"),
		AllowedUser:   allowedUser,
	}, nil
}

// запуск команд
func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if logLevel == "debug" {
		debugLog.Printf("Выполнена команда: %s %s", name, strings.Join(args, " "))
	}
	return string(output), err
}

// автоматический выбор IP
func getNextIP() (string, error) {
	file, err := os.Open("/etc/wireguard/clients/used_ips.txt")
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	defer file.Close()

	used := map[string]bool{}
	if file != nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			used[scanner.Text()] = true
		}
	}

	base := "10.0.0."
	for i := 2; i < 255; i++ {
		ip := fmt.Sprintf("%s%d", base, i)
		if !used[ip] {
			f, _ := os.OpenFile("/etc/wireguard/clients/used_ips.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			defer f.Close()
			f.WriteString(ip + "\n")
			return ip, nil
		}
	}
	return "", fmt.Errorf("нет доступных IP")
}

// генерация клиента
func createClientConf(clientName, wgInterface string) (string, error) {
	os.MkdirAll("/etc/wireguard/clients", 0700)
	clientConfPath := fmt.Sprintf("/etc/wireguard/clients/%s.conf", clientName)

	privateKeyBytes, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", fmt.Errorf("ошибка генерации приватного ключа: %v", err)
	}
	privateKey := strings.TrimSpace(string(privateKeyBytes))

	pubKeyCmd := exec.Command("wg", "pubkey")
	pubKeyCmd.Stdin = strings.NewReader(privateKey)
	pubKeyBytes, err := pubKeyCmd.Output()
	if err != nil {
		return "", fmt.Errorf("ошибка генерации публичного ключа: %v", err)
	}
	publicKey := strings.TrimSpace(string(pubKeyBytes))

	ip, err := getNextIP()
	if err != nil {
		return "", err
	}

	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/24
DNS = 1.1.1.1

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = <SERVER_IP>:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`, privateKey, ip)

	err = os.WriteFile(clientConfPath, []byte(conf), 0600)
	if err != nil {
		return "", fmt.Errorf("ошибка сохранения конфига: %v", err)
	}

	_, err = runCommand("sudo", "wg", "set", wgInterface, "peer", publicKey, "allowed-ips", ip+"/32")
	if err != nil {
		return "", fmt.Errorf("ошибка добавления клиента на сервер: %v", err)
	}

	_, err = runCommand("sudo", "wg-quick", "save", wgInterface)
	if err != nil {
		return "", fmt.Errorf("ошибка сохранения wg0.conf: %v", err)
	}

	return clientConfPath, nil
}

func main() {
	// логирование
	for _, arg := range os.Args {
		if arg == "-v" {
			logLevel = "info"
		}
		if arg == "-vv" {
			logLevel = "debug"
		}
	}
	infoLog = log.New(os.Stdout, "[INFO] ", log.Ldate|log.Ltime)
	debugLog = log.New(os.Stdout, "[DEBUG] ", log.Ldate|log.Ltime)

	config, err := loadConfig()
	if err != nil {
		log.Fatalf("[ERROR] %v", err)
	}

	if logLevel == "debug" {
		debugLog.Printf("Используемый TELEGRAM_TOKEN: %q", config.TelegramToken)
	}

	bot, err := tgbotapi.NewBotAPI(config.TelegramToken)
	if err != nil {
		log.Fatalf("[ERROR] Ошибка при авторизации бота: %v", err)
	}

	infoLog.Println("Запуск бота...")

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message == nil {
			continue
		}

		userID := update.Message.From.ID
		if userID != config.AllowedUser {
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "⛔ Доступ запрещён")
			bot.Send(msg)
			continue
		}

		if !update.Message.IsCommand() {
			continue
		}

		switch update.Message.Command() {
		case "help":
			helpMsg := `🤖 Доступные команды:
/status – показать статус WireGuard
/up – поднять интерфейс
/down – выключить интерфейс
/newclient <имя> – создать нового клиента WireGuard
/help – показать это сообщение`
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, helpMsg)
			bot.Send(msg)
			infoLog.Printf("Пользователь %d вызвал /help", userID)

		case "status":
			_, err := runCommand("sudo", "wg", "show")
			if err != nil {
				bot.Send(tgbotapi.NewMessage(update.Message.Chat.ID, "Ошибка получения статуса"))
			} else {
				bot.Send(tgbotapi.NewMessage(update.Message.Chat.ID, "✅ WireGuard работает"))
			}
			infoLog.Printf("Пользователь %d вызвал /status", userID)

		case "up":
			_, err := runCommand("sudo", "wg-quick", "up", config.WgInterface)
			if err != nil {
				bot.Send(tgbotapi.NewMessage(update.Message.Chat.ID, "Ошибка включения интерфейса"))
			} else {
				bot.Send(tgbotapi.NewMessage(update.Message.Chat.ID, "✅ Интерфейс поднят"))
			}
			infoLog.Printf("Пользователь %d вызвал /up", userID)

		case "down":
			_, err := runCommand("sudo", "wg-quick", "down", config.WgInterface)
			if err != nil {
				bot.Send(tgbotapi.NewMessage(update.Message.Chat.ID, "Ошибка выключения интерфейса"))
			} else {
				bot.Send(tgbotapi.NewMessage(update.Message.Chat.ID, "✅ Интерфейс выключен"))
			}
			infoLog.Printf("Пользователь %d вызвал /down", userID)

		case "newclient":
			args := update.Message.CommandArguments()
			if args == "" {
				bot.Send(tgbotapi.NewMessage(update.Message.Chat.ID, "⚠ Укажите имя клиента: /newclient <имя>"))
				continue
			}

			path, err := createClientConf(args, config.WgInterface)
			if err != nil {
				bot.Send(tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("Ошибка: %v", err)))
				continue
			}

			fileBytes, _ := os.ReadFile(path)
			doc := tgbotapi.FileBytes{Name: args + ".conf", Bytes: fileBytes}
			bot.Send(tgbotapi.NewDocument(update.Message.Chat.ID, doc))

			infoLog.Printf("Пользователь %d создал нового клиента %s", userID, args)
		}
	}
}
