package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"text/template"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	flag "github.com/spf13/pflag"
)

var (
	infoLog  *log.Logger
	debugLog *log.Logger
	logLevel string
)

func main() {
	verbose := flag.CountP("verbose", "v", "уровень логирования: -v или -vv")
	flag.Parse()

	switch *verbose {
	case 0:
		logLevel = "error"
	case 1:
		logLevel = "info"
	default:
		logLevel = "debug"
	}

	infoLog = log.New(log.Writer(), "[INFO] ", log.Ldate|log.Ltime)
	debugLog = log.New(log.Writer(), "[DEBUG] ", log.Ldate|log.Ltime)

	cfg := LoadConfig()

	if logLevel == "debug" {
		debugLog.Printf("Используемый TELEGRAM_TOKEN: %s", cfg.TelegramToken)
	}

	bot, err := tgbotapi.NewBotAPI(cfg.TelegramToken)
	if err != nil {
		log.Fatalf("[ERROR] Ошибка авторизации бота: %v", err)
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
		if userID != cfg.AllowedUser {
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "⛔ У вас нет доступа к боту.")
			bot.Send(msg)
			continue
		}

		if update.Message.IsCommand() {
			handleCommand(bot, update, cfg)
		}
	}
}

func handleCommand(bot *tgbotapi.BotAPI, update tgbotapi.Update, cfg *Config) {
	userID := update.Message.From.ID
	command := update.Message.Command()
	args := update.Message.CommandArguments()

	switch command {
	case "help":
		helpMsg := `🤖 Доступные команды:
/status – показать статус WireGuard
/up – поднять интерфейс
/down – выключить интерфейс
/newclient <имя> – создать нового клиента
/help – показать это сообщение`
		bot.Send(tgbotapi.NewMessage(update.Message.Chat.ID, helpMsg))
		infoLog.Printf("Пользователь %d вызвал /help", userID)

	case "status":
		_, err := runCommand("sudo", "wg", "show")
		if err != nil {
			bot.Send(tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("Ошибка: %v", err)))
		} else {
			bot.Send(tgbotapi.NewMessage(update.Message.Chat.ID, "✅ WireGuard работает"))
		}
		infoLog.Printf("Пользователь %d вызвал /status", userID)

	case "up":
		_, err := runCommand("sudo", "wg-quick", "up", cfg.WgInterface)
		if err != nil {
			bot.Send(tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("Ошибка: %v", err)))
		} else {
			bot.Send(tgbotapi.NewMessage(update.Message.Chat.ID, "✅ WireGuard поднят"))
		}
		infoLog.Printf("Пользователь %d вызвал /up", userID)

	case "down":
		_, err := runCommand("sudo", "wg-quick", "down", cfg.WgInterface)
		if err != nil {
			bot.Send(tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("Ошибка: %v", err)))
		} else {
			bot.Send(tgbotapi.NewMessage(update.Message.Chat.ID, "⛔ WireGuard остановлен"))
		}
		infoLog.Printf("Пользователь %d вызвал /down", userID)

	case "newclient":
		if args == "" {
			bot.Send(tgbotapi.NewMessage(update.Message.Chat.ID, "⚠ Укажите имя клиента: /newclient <имя>"))
			return
		}
		confPath, err := createClientConf(args, cfg)
		if err != nil {
			bot.Send(tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("Ошибка: %v", err)))
			infoLog.Printf("[ERROR] Пользователь %d попытался создать клиента %s: %v", userID, args, err)
		} else {
			content, _ := os.ReadFile(confPath)
			doc := tgbotapi.FileBytes{Name: args + ".conf", Bytes: content}
			bot.Send(tgbotapi.NewDocument(update.Message.Chat.ID, doc))
			infoLog.Printf("Пользователь %d создал клиента %s", userID, args)
		}
	}
}

func runCommand(name string, args ...string) (string, error) {
	if logLevel == "debug" {
		debugLog.Printf("Выполнена команда: %s %s", name, strings.Join(args, " "))
	}
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v\n%s", err, string(out))
	}
	return string(out), nil
}

func createClientConf(name string, cfg *Config) (string, error) {
	// Проверка существования директории
	if stat, err := os.Stat(cfg.ClientDir); os.IsNotExist(err) || !stat.IsDir() {
		return "", fmt.Errorf("директория для клиентов не найдена: %s", cfg.ClientDir)
	}

	clientConfPath := fmt.Sprintf("%s/%s.conf", cfg.ClientDir, name)

	// Генерация ключей
	privKey, err := runCommand("wg", "genkey")
	if err != nil {
		return "", err
	}
	privKey = strings.TrimSpace(privKey)

	pubKey, err := runCommand("wg", "pubkey")
	if err != nil {
		return "", err
	}
	pubKey = strings.TrimSpace(pubKey)

	ip, err := getNextIP(cfg)
	if err != nil {
		return "", err
	}

	_, err = runCommand("sudo", "wg", "set", cfg.WgInterface, "peer", pubKey, "allowed-ips", fmt.Sprintf("%s/32", ip))
	if err != nil {
		return "", err
	}

	tpl, err := template.ParseFiles("client.conf.tpl")
	if err != nil {
		return "", fmt.Errorf("ошибка чтения шаблона: %v", err)
	}

	f, err := os.Create(clientConfPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	data := struct {
		PrivateKey      string
		Address         string
		ServerPublicKey string
		ServerIP        string
	}{
		PrivateKey:      privKey,
		Address:         ip,
		ServerPublicKey: cfg.ServerPublicKey,
		ServerIP:        cfg.ServerIP,
	}

	err = tpl.Execute(f, data)
	if err != nil {
		return "", fmt.Errorf("ошибка генерации конфигурации: %v", err)
	}

	return clientConfPath, nil
}

// ---------------- IP Management ----------------

func getUsedIPs(cfg *Config) (map[string]bool, error) {
	out, err := exec.Command("sudo", "wg", "show", cfg.WgInterface, "dump").Output()
	if err != nil {
		return nil, fmt.Errorf("ошибка получения списка клиентов: %v", err)
	}

	used := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) >= 4 {
			for _, ip := range strings.Split(parts[3], ",") {
				used[strings.TrimSpace(ip)] = true
			}
		}
	}
	return used, nil
}

func getNextIP(cfg *Config) (string, error) {
	_, ipnet, err := net.ParseCIDR(cfg.WgSubnet)
	if err != nil {
		return "", fmt.Errorf("ошибка парсинга WG_SUBNET: %v", err)
	}

	used, err := getUsedIPs(cfg)
	if err != nil {
		return "", err
	}

	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		last := ip[3]
		if last < 10 {
			continue
		}
		candidate := fmt.Sprintf("%s/32", ip.String())
		if !used[candidate] {
			return ip.String(), nil
		}
	}

	return "", fmt.Errorf("свободных IP не осталось в %s", cfg.WgSubnet)
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
