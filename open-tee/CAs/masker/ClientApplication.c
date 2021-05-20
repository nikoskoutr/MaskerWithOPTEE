#include <tee_client_api.h>
#include <stdint.h>
#include <stdio.h>


static const TEEC_UUID uuid = {
    0x12345678, 0x8765, 0x4321, { 'M', 'A', 'S', 'K', '0', '0', '0', '2'}
};

#define MASKER 1

int main(int argc, char *argv[])
{
	char *sm_id;
	char *sm_seq;
	int consumption;
	unsigned char signature[256] = "";
	
	
	
	/* there should be at least 1 arg (consumption) for correct execution */
	if ( argc < 2 ) 
    {
        /* We print argv[0] assuming it is the program name */
        printf( "Usage: %s consumption id seq\n\
		consumption: consumption to be masked, range 0-40000, required\n\
		id: smart meter ID, 10 numerical digits, optional\n\
		seq:  mask sequence number, 3 numerical digits, optional\n", argv[0] );
    }
    else 
    {
		consumption=atoi(argv[1]);
		
		if ( argc > 2 ) 
			sm_id = argv[2];
		else
			sm_id = "1520160001";
		
		if ( argc > 3 ) 
			sm_seq = argv[3];
		else
			sm_seq = "211";
	}

	/*  Prepare the OP-TEE session and related parameters */
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	TEEC_Context ctx;
    TEEC_Session sess;

	res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	}

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, origin);
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT, TEEC_MEMREF_TEMP_INOUT);
	op.params[0].tmpref.buffer = sm_id;
	op.params[0].tmpref.size = strlen(sm_id);
	op.params[1].tmpref.buffer = sm_seq;
	op.params[1].tmpref.size = strlen(sm_seq);
	op.params[2].value.a = consumption;
	op.params[3].tmpref.buffer = signature;
	op.params[3].tmpref.size = 256;
	
	res = TEEC_InvokeCommand(&sess, MASKER, &op, &origin);
	printf("test\n");
	if (res != TEEC_SUCCESS) {
    	errx(1, "TEEC_InvokeCommand(GENERATE_KEY) failed 0x%x origin 0x%x", res, origin);
	}

	printf("The signature is: %s", signature);


	TEEC_CloseSession(&sess);
  	TEEC_FinalizeContext(&ctx);

	return 0;
}