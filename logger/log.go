/*
 * @Description:
 * @LastEditors: ayu
 */
package logger

import (
	"fmt"
	"path"
	"strings"

	"io"
	"os"
	"runtime"
	"time"

	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"github.com/sirupsen/logrus"
)

var (
	Log *logrus.Logger
)

// func init() {
// 	Log = logrus.New()
// 	SetDefault("", "info")
// }

func InitLog(logLevel string) {
	Log = logrus.New()
	SetDefault("", logLevel)
}

/**
 * @description: 使用需要自定义相关配置
 * @param {string} logPath 日志路径
 * @param {string} logLevel 日志等级  info warn
 * @return {*}
 */
func SetDefault(logPath string, logLevel string) {
	//日志等级
	var level logrus.Level
	log_level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		level = logrus.InfoLevel
	} else {
		level = log_level
	}
	Log.SetLevel(level)
	//debug模式
	if level == logrus.DebugLevel {
		Log.SetReportCaller(true)
		// 日志格式
		Log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.DateTime,
			ForceColors:     true,
			ForceQuote:      true,
			CallerPrettyfier: func(frame *runtime.Frame) (function string, file string) {
				//仅需基本函数名+文件名与行号
				fileName := path.Base(frame.File)
				function_new := frame.Function[strings.LastIndex(frame.Function, "/")+1:]
				return function_new, fmt.Sprintf("%s:%d", fileName, frame.Line)
			},
		})
	}

	//日志存储
	if len(logPath) > 0 {
		writer, err := rotatelogs.New(
			logPath+"-%Y%m%d%H%M",
			rotatelogs.WithLinkName(logPath), // 生成软链，指向最新日志文件
			//MaxAge and RotationCount cannot be both set  两者不能同时设置
			//rotatelogs.WithMaxAge(15*24*time.Hour),    //默认清理存在15天以上的文件
			rotatelogs.WithRotationCount(5), //number 默认7份 大于7份 或到了清理时间 开始清理
			//rotatelogs.WithRotationTime(time.Hour*24), //rotate 默认每24小时生成一份新的日志文件
			rotatelogs.WithRotationSize(50*1024*1024),
		)
		if err != nil {
			panic(err)
		}
		Log.SetOutput(io.MultiWriter(writer, os.Stderr))
	}

}
