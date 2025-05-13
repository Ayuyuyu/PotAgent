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

	err = vpconfig.ReadInConfig()
	if err != nil {
		panic(fmt.Sprintf("读取配置 %v 失败。 %v", confPath, err))
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
	err := viperConf.Unmarshal(interfaceConf)
	if err != nil {
		panic(fmt.Sprintf("解析配置失败 %v", err.Error()))
	}
	return nil
}
