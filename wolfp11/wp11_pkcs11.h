/* wolfP11
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfP11.
 *
 * wolfP11 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfP11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * For a commercial license, contact wolfSSL Inc. at licensing@wolfssl.com.
 */

/* wp11_pkcs11.h -- wolfP11 PKCS#11 2.40 public declarations
 *
 * Includes the standard PKCS#11 type definitions from p11-kit and
 * declares wolfP11's C_* entry points.
 *
 * Callers that load libwolfp11.so at runtime only need C_GetFunctionList;
 * all other functions are accessible through the returned CK_FUNCTION_LIST.
 */

#ifndef WOLFP11_PKCS11_H
#define WOLFP11_PKCS11_H

/* Use the standard PKCS#11 header from p11-kit for all type definitions. */
#include <p11-kit/pkcs11.h>
#include <stdint.h>
#include <stddef.h>

/* PKCS#11 3.0 EdDSA constants -- not yet in the p11-kit headers we build
 * against.  Guarded with #ifndef so a future p11-kit update that adds them
 * does not produce a redefinition error. */
#ifndef CKM_EC_EDWARDS_KEY_PAIR_GEN
#define CKM_EC_EDWARDS_KEY_PAIR_GEN  (0x00001055UL)
#endif
#ifndef CKK_EC_EDWARDS
#define CKK_EC_EDWARDS               (0x00000040UL)
#endif
#ifndef CKM_EDDSA
#define CKM_EDDSA                    (0x00001057UL)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Bootstrap entry point -- must be the only symbol required by dlopen users */
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

/* All other C_* functions are exposed through the function list returned
 * by C_GetFunctionList.  They are also exported as symbols for static
 * linking convenience. */

CK_RV C_Initialize(CK_VOID_PTR pInitArgs);
CK_RV C_Finalize(CK_VOID_PTR pReserved);
CK_RV C_GetInfo(CK_INFO_PTR pInfo);

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
                     CK_ULONG_PTR pulCount);
CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);

CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
                          CK_MECHANISM_TYPE_PTR pMechanismList,
                          CK_ULONG_PTR pulCount);
CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
                          CK_MECHANISM_INFO_PTR pInfo);

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin,
                   CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin,
                 CK_ULONG ulPinLen);
CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
                CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin,
                CK_ULONG ulNewLen);

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
                     CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                     CK_SESSION_HANDLE_PTR phSession);
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);
CK_RV C_CloseAllSessions(CK_SLOT_ID slotID);
CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession,
                        CK_SESSION_INFO_PTR pInfo);
CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,
                           CK_BYTE_PTR pOperationState,
                           CK_ULONG_PTR pulOperationStateLen);
CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,
                           CK_BYTE_PTR pOperationState,
                           CK_ULONG ulOperationStateLen,
                           CK_OBJECT_HANDLE hEncryptionKey,
                           CK_OBJECT_HANDLE hAuthenticationKey);

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
               CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
CK_RV C_Logout(CK_SESSION_HANDLE hSession);

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession,
                      CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                      CK_OBJECT_HANDLE_PTR phObject);
CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                    CK_OBJECT_HANDLE_PTR phNewObject);
CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                       CK_ULONG_PTR pulSize);
CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession,
                           CK_OBJECT_HANDLE hObject,
                           CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession,
                           CK_OBJECT_HANDLE hObject,
                           CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession,
                         CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV C_FindObjects(CK_SESSION_HANDLE hSession,
                     CK_OBJECT_HANDLE_PTR phObject,
                     CK_ULONG ulMaxObjectCount,
                     CK_ULONG_PTR pulObjectCount);
CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession);

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                     CK_OBJECT_HANDLE hKey);
CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                 CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
                 CK_ULONG_PTR pulEncryptedDataLen);
CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                       CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                       CK_ULONG_PTR pulEncryptedPartLen);
CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR pLastEncryptedPart,
                      CK_ULONG_PTR pulLastEncryptedPartLen);

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                     CK_OBJECT_HANDLE hKey);
CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
                 CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
                 CK_ULONG_PTR pulDataLen);
CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
                       CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                       CK_ULONG_PTR pulPartLen);
CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
                      CK_ULONG_PTR pulLastPartLen);

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
                CK_ULONG_PTR pulDigestLen);
CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                      CK_ULONG ulPartLen);
CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
                     CK_ULONG_PTR pulDigestLen);

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hKey);
CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
              CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
              CK_ULONG_PTR pulSignatureLen);
CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                    CK_ULONG ulPartLen);
CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                   CK_ULONG_PTR pulSignatureLen);
CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession,
                         CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                     CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                     CK_ULONG_PTR pulSignatureLen);

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                    CK_OBJECT_HANDLE hKey);
CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                CK_ULONG ulSignatureLen);
CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                      CK_ULONG ulPartLen);
CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                     CK_ULONG ulSignatureLen);
CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
                           CK_MECHANISM_PTR pMechanism,
                           CK_OBJECT_HANDLE hKey);
CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                       CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
                       CK_ULONG_PTR pulDataLen);

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                              CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                              CK_ULONG_PTR pulEncryptedPartLen);
CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pEncryptedPart,
                              CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                              CK_ULONG_PTR pulPartLen);
CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                           CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                           CK_ULONG_PTR pulEncryptedPartLen);
CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pEncryptedPart,
                              CK_ULONG ulEncryptedPartLen,
                              CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                     CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                     CK_OBJECT_HANDLE_PTR phKey);
CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
                          CK_MECHANISM_PTR pMechanism,
                          CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                          CK_ULONG ulPublicKeyAttributeCount,
                          CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                          CK_ULONG ulPrivateKeyAttributeCount,
                          CK_OBJECT_HANDLE_PTR phPublicKey,
                          CK_OBJECT_HANDLE_PTR phPrivateKey);
CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                 CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
                 CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                   CK_OBJECT_HANDLE hUnwrappingKey,
                   CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen,
                   CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
                   CK_OBJECT_HANDLE_PTR phKey);
CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                   CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
                   CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed,
                    CK_ULONG ulSeedLen);
CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData,
                        CK_ULONG ulRandomLen);

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession);
CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession);
CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
                          CK_VOID_PTR pRserved);

#ifdef WOLFP11_CFG_USB_BACKEND
/* wolfP11 extension: retrieve a YubiKey PIV attestation certificate.
 * Not part of the standard PKCS#11 interface.
 * slot_id:  PKCS#11 slot that owns the token (must be logged in via C_Login)
 * piv_slot: WP11_PIV_SLOT_* constant (key slot to attest)
 * der/derlen: output buffer; *derlen updated to actual length.
 * Returns WP11_PIV_OK (0) on success, negative WP11_PIV_ERR_* on failure. */
int wp11_piv_attest_slot(CK_SLOT_ID  slot_id,
                         uint8_t     piv_slot,
                         uint8_t    *der,
                         size_t     *derlen);
#endif /* WOLFP11_CFG_USB_BACKEND */

#ifdef __cplusplus
}
#endif

#endif /* WOLFP11_PKCS11_H */
