#include <se_ta.h>
#include <string.h>
#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>

#define MAX_RSA_KEYSIZE 2048
#define MASKER 1

TEE_Result gen_randoms(int size_bits, unsigned char * mask)
{
	TEE_Result ret = TEE_SUCCESS;

	int size_bytes = size_bits / 8;

	ret = TEE_GenerateRandom(mask, size_bytes);
	if (ret != TEE_SUCCESS) {
    	EMSG("TEE_GenerateRandom failed: 0x%x", ret);
    	return ret;
  	}

	return ret;
}

int doSign(unsigned char * sm_id; unsigned char * data, int dataLen, unsigned char * signature, int * singatureLen)
{
	TEE_Result ret = TEE_SUCCESS;

	unsigned char digest[33] = "";
	int digestLen = 0;

	// Calculate hash
	TEE_OperationHandle dig_operation = NULL;
	ret = TEE_AllocateOperation(&dig_operation, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (ret != TEE_SUCCESS) {
		DMSG("TEE_AllocateOperation failed: 0x%x", ret);
		TEE_FreeOperation(dig_operation);
		return ret;
	}

	ret = TEE_DigestDoFinal(dig_operation, data, dataLen, digest, &digestLen);
	if (ret != TEE_SUCCESS) {
		DMSG("TEE_AllocateOperation failed: 0x%x", ret);
		TEE_FreeOperation(dig_operation);
	}

	TEE_FreeOperation(dig_operation);

	// If key exists for smart meter ID then fetch it
	TEE_ObjectHandle key;

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, sm_id, strlen(sm_id), TEE_DATA_FLAG_ACCESS_READ, &key);
	if (ret != TEE_SUCCESS) {
		DMSG("TEE_OpenPersistentObject failed: 0x%x", ret);
		// If there is no key, then generate and store it
		TEE_ObjectHandle temp_key = NULL;
		res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, MAX_RSA_KEYSIZE, &temp_key);
		if (res) {
			EMSG("TEE_AllocateTransientObject(%#" PRIx32 ", %" PRId32 "): %#" PRIx32, key_type, key_size, res);
			return res;
		}

		res = TEE_GenerateKey(temp_key, MAX_RSA_KEYSIZE, NULL, 0);
		if (res) {
			EMSG("TEE_GenerateKey(%" PRId32 "): %#" PRIx32, key_size, res);
			TEE_FreeTransientObject(temp_key);
			return res;
		}

		ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, sm_id, strlen(sm_id), NULL, temp_key, NULL, 0, &key);
		if (ret != TEE_SUCCESS) {
			DMSG("TEE_CreatePersistentObject failed: 0x%x", ret);
			TEE_FreeTransientObject(temp_key);
			return ret;
		}

		TEE_CloseObject(temp_key);
	}
	

	// Sign the hash
	TEE_OperationHandle rsa_operation = NULL;
	ret = TEE_AllocateOperation(&rsa_operation, SIGN_RSASSA_MGF, TEE_MODE_SIGN, MAX_RSA_KEYSIZE);
	if (ret != TEE_SUCCESS) {
		EMSG("TEE_AllocateOperation failed: 0x%x", ret);
		TEE_FreeOperation(rsa_operation);
		return ret;
	}
	ret = TEE_AsymmetricSignDigest(rsa_operation, NULL, 0, digest, digestLen, signature, signatureLen);
    if (ret != TEE_SUCCESS) {
      DMSG("TEE_AsymmetricSignDigest failed: 0x%x", ret);
	  TEE_FreeOperation(rsa_operation);
    }

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
	unsigned char signature[2048]; // Buffer used to return the signature to the normal world
	int signatureLen = 0; // The size of the signature

	do {
		unsigned char gened_mask[32]; // Temporary mask generation buffer
		ret = gen_randoms(256, gened_mask)
		if (ret != TEE_SUCCESS) {
    		EMSG("gen_randoms failed: 0x%x", ret);
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
	ret = doSign(atoi(sm_id), dt_to_sign, dataLen, signature, &signatureLen); 
	return ret;
}

/*******************************************************************************
 * Mandatory TA functions.
 ******************************************************************************/
TEE_Result TA_CreateEntryPoint(void) {
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types, TEE_Param __unused params[4],
				    void __unused **sess_ctx) {
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *sess_ctx) {
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx, uint32_t cmd_id,
                                      uint32_t param_types, TEE_Param params[4]) 
{
	if(cmd_id == MASKER) { // TODO: ADD MASKER COMMAND ID
    return masker(param_types, params);
  } else {
    return TEE_ERROR_BAD_PARAMETERS;
	}
}