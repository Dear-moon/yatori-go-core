package examples

import (
	"bufio"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/yatori-dev/yatori-go-core/api/mooc"
)

func TestMOOC(t *testing.T) {
	if os.Getenv("YATORI_MOOC_INTEGRATION") != "1" {
		t.Skip("requires authorized real account / trace")
	}
	account := os.Getenv("YATORI_MOOC_ACCOUNT")
	if account == "" {
		t.Skip("requires authorized real account / trace")
	}
	client, err := mooc.NewMOOCClient(account, mooc.ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx := context.Background()
	if err := client.SendSMS(ctx); err != nil {
		t.Fatal(err)
	}
	t.Log("Enter the SMS code in the terminal.")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		t.Fatal("unable to read SMS code")
	}
	if _, err := client.LoginSMS(ctx, strings.TrimSpace(line)); err != nil {
		t.Fatal(err)
	}
}
