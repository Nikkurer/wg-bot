package main

import (
	"log"
	"os"
	"strconv"
)

type Config struct {
	TelegramToken   string
	WgInterface     string
	AllowedUser     int64
	ServerIP        string
	ServerPublicKey string
	WgSubnet        string
	ClientDir       string
}

func LoadConfig() *Config {
	allowedUserStr := os.Getenv("ALLOWED_USER")
	if allowedUserStr == "" {
		log.Fatal("[ERROR] ALLOWED_USER не задан")
	}
	allowedUser, err := strconv.ParseInt(allowedUserStr, 10, 64)
	if err != nil {
		log.Fatalf("[ERROR] Неверный ALLOWED_USER: %v", err)
	}

	cfg := &Config{
		TelegramToken:   os.Getenv("TELEGRAM_TOKEN"),
		WgInterface:     os.Getenv("WG_INTERFACE"),
		AllowedUser:     allowedUser,
		ServerIP:        os.Getenv("SERVER_IP"),
		ServerPublicKey: os.Getenv("SERVER_PUBLIC_KEY"),
		WgSubnet:        os.Getenv("WG_SUBNET"),
		ClientDir:       os.Getenv("CLIENT_DIR"),
	}

	if cfg.TelegramToken == "" || cfg.WgInterface == "" || cfg.ServerIP == "" ||
		cfg.ServerPublicKey == "" || cfg.WgSubnet == "" || cfg.ClientDir == "" {
		log.Fatal("[ERROR] Не заданы обязательные переменные окружения (TELEGRAM_TOKEN, WG_INTERFACE, SERVER_IP, SERVER_PUBLIC_KEY, WG_SUBNET, ALLOWED_USER, CLIENT_DIR)")
	}

	return cfg
}
