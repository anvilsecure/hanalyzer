package ssh

type SSHError struct {
	errorCode    int
	errorMessage string
}

func (err *SSHError) Code() int {
	return err.errorCode
}
func (err *SSHError) Error() string {
	return err.errorMessage
}

var (
	NoSuchFileOrDirectory = SSHError{
		errorCode:    2,
		errorMessage: "Process exited with status 2",
	}
)
