/*
 * @Description:
 * @LastEditors:
 */
package config

import (
	"fmt"

	"github.com/spf13/viper"
)

/**
 * @description: 初始化viper的读取
 * @param {string} confPath 文件路径
 * @return {*}
 */
func YamlConfigHandle(confPath string) (conf *viper.Viper, err error) {
	vpconfig := viper.New()
	vpconfig.SetConfigType("yaml")
	vpconfig.SetConfigFile(confPath)

	// 返回错误而不是 panic：配置文件缺失/语法错误是最常见的启动问题，
	// 调用方需要一条可读的错误提示，而不是带 goroutine 栈的崩溃。
	if err := vpconfig.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("读取配置 %s 失败: %w", confPath, err)
	}

	return vpconfig, nil
}

/**
 * @description: 读取配置信息到结构体
 * @param {*viper.Viper} viperConf
 * @param {interface{}} interfaceConf
 * @return {*}
 */
func ReadConfigFile(viperConf *viper.Viper, interfaceConf interface{}) error {
	// 使用 viperConf.Unmarshal 方法将配置数据解析到 interfaceConf 中。
	if err := viperConf.Unmarshal(interfaceConf); err != nil {
		return fmt.Errorf("解析配置失败: %w", err)
	}

	return nil
}
