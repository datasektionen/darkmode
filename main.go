package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"

)

func is_dakrmode(c *gin.Context) {
	darkmode, ok := os.LookupEnv("DARKMODE")
	if !ok {
		darkmode = "false"
	}
	
	c.String(http.StatusOK, darkmode)
}

func main() {
	r := gin.Default()

	api := r.Group("/api")

	api.GET("/is_darkmode", is_dakrmode)

	port, err := strconv.Atoi(os.Getenv("PORT"))
	if err != nil {
		fmt.Println(err)
	}

	r.Run(fmt.Sprintf(":%d", port))
}