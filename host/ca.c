#include <tee_client_api.h>
#include <se_ta.h>
#include <stdint.h>
#include <stdio.h>

#define MASKER 1

struct test_ctx
{
  TEEC_Context ctx;
  TEEC_Session sess;
};

void prepare_tee_session(struct test_ctx *ctx)
{
  TEEC_UUID uuid = TA_SE_UUID;
  uint32_t origin;
  TEEC_Result res;

  /* Initialize a context connecting us to the TEE */
  res = TEEC_InitializeContext(NULL, &ctx->ctx);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

  /* Open a session with the TA */
  res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
                         TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
         res, origin);
}

void terminate_tee_session(struct test_ctx *ctx)
{
  TEEC_CloseSession(&ctx->sess);
  TEEC_FinalizeContext(&ctx->ctx);
}

int main(int argc, char *argv[])
{
	char *sm_id;
	char *sm_seq;
	int consumption;
	char signature[2048];
	
	/* OP-TEE Vars */
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	struct test_ctx ctx = {};
	
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
	prepare_tee_session(&ctx);
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
									TEEC_MEMREF_TEMP_INPUT,
									TEEC_VALUE_INOUT,
									TEEC_MEMREF_TEMP_OUTPUT);
	op.params[0].tmpref.buffer = sm_id;
	op.params[0].tmpref.size = strlen(sm_id);
	op.params[1].tmpref.buffer = sm_seq;
	op.params[1].tmpref.size = strlen(sm_seq);
	op.params[2].value.a = consumption;
	op.params[3].tmpref.buffer = signature;
	
	res = TEEC_InvokeCommand(&ctx->sess, MASKER, &op, &origin);
	if (res != TEEC_SUCCESS) {
    	errx(1, "TEEC_InvokeCommand(GENERATE_KEY) failed 0x%x origin 0x%x", res, origin);
	}

	printf("The signature is: %s", signature);

	terminate_tee_session(&ctx);
	return 0;
}