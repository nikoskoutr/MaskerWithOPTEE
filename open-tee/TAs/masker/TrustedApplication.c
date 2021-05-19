#include <string.h>
#include <tee_internal_api.h>
#include <stdio.h>
#include "tee_logging.h"

#ifdef TA_PLUGIN
#include "tee_ta_properties.h"

/* UUID must be unique */
SET_TA_PROPERTIES(
    { 0x12345678, 0x8765, 0x4321, { 'M', 'A', 'S', 'K', '0', '0', '0', '2'} }, /* UUID */
        2048, /* dataSize */
        2048, /* stackSize */
        1, /* singletonInstance */
        1, /* multiSession */
        1) /* instanceKeepAlive */
#endif

#define MAX_RSA_KEYSIZE 2048
#define MASKER 1

TEE_Result gen_randoms(int size_bits, unsigned char * mask)
{
	TEE_Result ret = TEE_SUCCESS;

	int size_bytes = size_bits / 8;

	TEE_GenerateRandom(mask, size_bytes);
	printf("Generated Randoms\n");

	return ret;
}

int doSign(unsigned char * sm_id, unsigned char * data, int dataLen, unsigned char * signature, int * signatureLen)
{
	TEE_Result ret = TEE_SUCCESS;

	unsigned char digest[64] = "";
	int digestLen = 64;

	// Calculate hash
	TEE_OperationHandle dig_operation = NULL;
	ret = TEE_AllocateOperation(&dig_operation, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (ret != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateOperation failed");
		TEE_FreeOperation(dig_operation);
		return ret;
	}

	if(!digest){
		OT_LOG(LOG_ERR, "BEFORE DIGEST IS NULL");
	}

	ret = TEE_DigestDoFinal(dig_operation, data, dataLen, digest, &digestLen);
	if (ret != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateOperation failed");
		TEE_FreeOperation(dig_operation);
	}

	if(!digest){
		OT_LOG(LOG_ERR, "AFTER IS NULL");
	}

	TEE_FreeOperation(dig_operation);

	if(!digest){
		OT_LOG(LOG_ERR, "AFTER AFTER DIGEST IS NULL");
	}

	OT_LOG(LOG_ERR, "Data: %s, Digest: %s", data, digest);

	if(!digest){
		OT_LOG(LOG_ERR, "AFTER AFTER AFTER DIGEST IS NULL");
	}

	// If key exists for smart meter ID then fetch it
	TEE_ObjectHandle key;

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, sm_id, strlen(sm_id), TEE_DATA_FLAG_SHARE_READ, &key);
	if (ret != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_OpenPersistentObject failed");
		// If there is no key, then generate and store it
		TEE_ObjectHandle temp_key = NULL;
		ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, MAX_RSA_KEYSIZE, &temp_key);
		if (ret) {
			OT_LOG(LOG_ERR, "TEE_AllocateTransientObject()");
			return ret;
		}

		ret = TEE_GenerateKey(temp_key, MAX_RSA_KEYSIZE, NULL, 0);
		if (ret) {
			OT_LOG(LOG_ERR, "TEE_AllocateTransientObject()");
			TEE_FreeTransientObject(temp_key);
			return ret;
		}

		ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, sm_id, strlen(sm_id), NULL, temp_key, NULL, 0, &key);
		if (ret != TEE_SUCCESS) {
			OT_LOG(LOG_ERR, "TEE_CreatePersistentObject failed");
			TEE_FreeTransientObject(temp_key);
			return ret;
		}

		TEE_CloseObject(temp_key);
	}
	

	// Sign the hash
	TEE_OperationHandle rsa_operation = NULL;
	ret = TEE_AllocateOperation(&rsa_operation, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, TEE_MODE_SIGN, MAX_RSA_KEYSIZE);
	if (ret != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateOperation failed");
		TEE_FreeOperation(rsa_operation);
		TEE_CloseObject(key);
		return ret;
	}

	ret = TEE_SetOperationKey(rsa_operation, key);
	if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "TEE_SetOperationKey failed");
	  TEE_FreeOperation(rsa_operation);
	  TEE_CloseObject(key);
    }
	if(!digest){
		OT_LOG(LOG_ERR, "DIGEST IS NULL");
	}

	if(!signature){
		OT_LOG(LOG_ERR, "DIGEST IS NULL");
	}
	ret = TEE_AsymmetricSignDigest(rsa_operation, NULL, 0, digest, digestLen, signature, signatureLen);
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "TEE_AsymmetricSignDigest failed");
	  TEE_FreeOperation(rsa_operation);
	  TEE_CloseObject(key);
    }

	TEE_CloseObject(key);
	TEE_FreeOperation(rsa_operation);
	return ret;
}

int masker(uint32_t param_types, TEE_Param * params) {

	TEE_Result ret = TEE_SUCCESS;
	
	char * sm_id = params[0].memref.buffer; // Get smart meter ID from the client applications
	char * sm_seq = params[1].memref.buffer; // Get smart meter sequence number from the client applications
	int consumption = params[2].value.a; // Get smart meter consumption from the client applications
	int mask; // Randomly generated mask 
	char mask_buffer[5]=""; // Buffer to store the mask in a char format
	unsigned char dt_to_sign[18]=""; // Buffer that holds the data to sign
	size_t dataLen; // To be used to determine the size of the data to be signed
	unsigned char signature = params[3].memref.buffer; // Buffer used to return the signature to the normal world
	size_t signatureLen = 2048; // The size of the signature

	if(!mask_buffer) {
		OT_LOG(LOG_ERR,"mask_buffer is null!!");
	}

	do {
		unsigned char gened_mask[32]; // Temporary mask generation buffer
		ret = gen_randoms(256, gened_mask);
		if (ret != TEE_SUCCESS) {
    		OT_LOG(LOG_ERR, "gen_randoms failed");
    		return ret;
  		}
		  
		for(int j = 0; (mask < 40960 || mask > 65535) && j < 32; j = j + 2)
		{
			mask = (int) gened_mask[j] << 8 | (int) gened_mask[j+1];	
			mask = mask + consumption;
		}		
	} while (mask < 40960 || mask > 65535);
		
	
	sprintf(mask_buffer, "%d", mask); // Transform the integer mask to a char array
	
	strncpy(dt_to_sign, sm_id, 10); // Add smart meter ID to the data to sign
	strncat(dt_to_sign, mask_buffer, 5); // Add random mask reading to the data to sign
	strncat(dt_to_sign, sm_seq, 3); // Add smart meter seqence number to the data to sign
	
	dataLen = strlen(dt_to_sign);
	ret = doSign(sm_id, dt_to_sign, dataLen, signature, &signatureLen); 
	return ret;
}

/*******************************************************************************
 * Mandatory TA functions.
 ******************************************************************************/

TEE_Result TA_CreateEntryPoint(void)
{
     OT_LOG(LOG_ERR, "Open Session to TEE");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
     OT_LOG(LOG_ERR, "Destroy Session to TEE");
}


TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
        TEE_Param  params[4], void **sess_ctx)
{

    (void)&params;
    (void)&sess_ctx;
    return TEE_SUCCESS;
}


void TA_CloseSessionEntryPoint(void *sess_ctx)

{
    (void)&sess_ctx;
}

TEE_Result TA_InvokeCommandEntryPoint(void * sess_ctx, uint32_t cmd_id, uint32_t param_types, TEE_Param params[4]) 
{
	if(cmd_id == MASKER) { // TODO: ADD MASKER COMMAND ID
	printf("Entered TEE\n");
    return masker(param_types, params);
  } else {
    return TEE_ERROR_BAD_PARAMETERS;
	}
}