package main

import (
	"fmt"
	"os"
	"potAgent/imp"
	"potAgent/logger"

	_ "potAgent/services/http"
	_ "potAgent/services/ssh"
	_ "potAgent/services/telnet"
	_ "potAgent/services/vnc"

	"github.com/urfave/cli/v2"
)

var (
	buildTime    string
	buildVersion string
	buildMode    string
)

var cliFlags = []cli.Flag{
	&cli.StringFlag{
		Name:  "config, c",
		Value: "pot.yaml",
		Usage: "Load configuration from `FILE`",
	},
	&cli.StringFlag{
		Name:  "data, d",
		Value: "~/.potAgent",
		Usage: "Store data in `DIR`",
	},
}

func runServe(c *cli.Context) error {
	configCandidates := []string{
		c.String("config"),
		"./pot.yaml",
	}
	successful := false
	for _, candidate := range configCandidates {
		logger.Log.Debugf("Using config file %s\n", candidate)
		successful = true
		break
	}
	if !successful {
		return cli.Exit("No configuration file found! Check your config (-c).", 1)
	}
	//
	imp.InitServicesRun(c.String("config"))

	//ctx, cancel := context.WithCancel(context.Background())

	return nil
}
func main() {
	logger.InitLog(buildMode)
	//logger.InitLog("Debug")
	description := fmt.Sprintf("potAgent for low interact honeypot\n Build Time: %s\n Build Version: %s\n", buildTime, buildVersion)
	app := &cli.App{
		Name:        "honeypot agent",
		Usage:       "potAgent flags here",
		Description: description,
		Flags:       cliFlags,
		Action:      runServe,
	}

	if err := app.Run(os.Args); err != nil {
		logger.Log.Fatal(err)
	}
}
