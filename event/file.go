package event

import (
	"fmt"
	"os"
	"potAgent/global"
	"potAgent/logger"
)

var fileHanle *os.File

/*
*@Description: 初始化文件推送
*@param opt
*@return bool
 */
func newFilePusher(opt *global.Options) bool {
	if !opt.Outputs.File.Enable {
		logger.Log.Warn("file push not enable")
		return false
	}
	file, err := os.OpenFile(opt.Outputs.File.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, os.ModePerm)
	if err != nil {
		logger.Log.Error("打开文件失败", err.Error())
		return false
	}
	fileHanle = file
	//defer file.Close()
	go func() {
		for e := range c {
			if e == "" {
				return
			}
			err := fileWrite(e)
			if err != nil {
				logger.Log.Error(err)
			}
		}
	}()
	return true
}

func fileWrite(data string) error {
	if fileHanle == nil {
		return fmt.Errorf("nil file handle")
	}
	_, err := fileHanle.WriteString(data + "\n")
	if err != nil {
		logger.Log.Error("Error writing to file:", err)
		return err
	}
	return err
}

func fileClose() {
	if fileHanle != nil {
		fileHanle.Close()
	}
}
