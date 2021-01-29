#include "detect.h"

int main(int argc, char** argv)
{
	printf("wsb_detect_username = %d\n", wsb_detect_username());
	printf("wsb_detect_proc = %d\n", wsb_detect_proc());
	printf("wsb_detect_suffix = %d\n", wsb_detect_suffix());
	printf("wsb_detect_dev = %d\n", wsb_detect_dev());
	printf("wsb_detect_genuine = %d\n", wsb_detect_genuine());
	printf("wsb_detect_cmd = %d\n", wsb_detect_cmd());
	return ERROR_SUCCESS;
}
