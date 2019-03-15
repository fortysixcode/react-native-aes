//
//  AesCrypt.m
//
//  Created by tectiv3 on 10/02/17.
//  Copyright © 2017 tectiv3. All rights reserved.
//

#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonKeyDerivation.h>

#import "AesCrypt.h"

@implementation AesCrypt

+ (NSString *) toHex:(NSData *)nsdata {
    NSString * hexStr = [NSString stringWithFormat:@"%@", nsdata];
    for(NSString * toRemove in [NSArray arrayWithObjects:@"<", @">", @" ", nil])
        hexStr = [hexStr stringByReplacingOccurrencesOfString:toRemove withString:@""];
    return hexStr;
}

+ (NSData *) fromHex: (NSString *)string {
    NSMutableData *data = [[NSMutableData alloc] init];
    unsigned char whole_byte;
    char byte_chars[3] = {'\0','\0','\0'};
    for (int i = 0; i < ([string length] / 2); i++) {
        byte_chars[0] = [string characterAtIndex:i*2];
        byte_chars[1] = [string characterAtIndex:i*2+1];
        whole_byte = strtol(byte_chars, NULL, 16);
        [data appendBytes:&whole_byte length:1];
    }
    return data;
}

+ (NSString *) pbkdf2:(NSString *)password salt: (NSString *)salt cost: (NSInteger)cost length: (NSInteger)length {
    // Data of String to generate Hash key(hexa decimal string).
    NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
    NSData *saltData = [self fromHex:salt];

    // Hash key (hexa decimal) string data length.
    NSMutableData *hashKeyData = [NSMutableData dataWithLength:length/8];

    // Key Derivation using PBKDF2 algorithm.
    int status = CCKeyDerivationPBKDF(
                    kCCPBKDF2,
                    passwordData.bytes,
                    passwordData.length,
                    saltData.bytes,
                    saltData.length,
                    kCCPRFHmacAlgSHA256,
                    cost,
                    hashKeyData.mutableBytes,
                    hashKeyData.length);

    if (status == kCCParamError) {
        NSLog(@"Key derivation error");
        return @"";
    }

    return [self toHex:hashKeyData];
}

+ (NSData *)AES128CBC: (NSString* )operation data: (NSData *)data key: (NSString *)key iv: (NSString *)iv {
    NSData *keyData = [self fromHex:key];
    NSData *ivData = [self fromHex:iv];
    
    size_t dataOutMoved = 0;
    size_t dataOutMovedTotal = 0;
    CCCryptorStatus ccStatus = 0;
    CCCryptorRef cryptor = NULL;
    
    ccStatus = CCCryptorCreateWithMode([operation isEqualToString:@"encrypt"] ? kCCEncrypt : kCCDecrypt,
                                       kCCModeCTR,
                                       kCCAlgorithmAES,
                                       ccNoPadding,
                                       ivData.bytes, keyData.bytes,
                                       kCCKeySizeAES256,
                                       NULL, 0, 0, // tweak XTS mode, numRounds
                                       kCCModeOptionCTR_BE, // CCModeOptions
                                       &cryptor);
    
    if (cryptor == 0 || ccStatus != kCCSuccess) {
        NSLog(@"CCCryptorCreate status: %d", ccStatus);
        CCCryptorRelease(cryptor);
        return nil;
    }
    
    size_t dataOutLength = CCCryptorGetOutputLength(cryptor, data.length, true);
    NSMutableData *dataOut = [NSMutableData dataWithLength:dataOutLength];
    char *dataOutPointer = (char *)dataOut.mutableBytes;
    
    ccStatus = CCCryptorUpdate(cryptor,
                               data.bytes, data.length,
                               dataOutPointer, dataOutLength,
                               &dataOutMoved);
    dataOutMovedTotal += dataOutMoved;
    
    if (ccStatus != kCCSuccess) {
        NSLog(@"CCCryptorUpdate status: %d", ccStatus);
        CCCryptorRelease(cryptor);
        return nil;
    }
    
    ccStatus = CCCryptorFinal(cryptor,
                              dataOutPointer + dataOutMoved, dataOutLength - dataOutMoved,
                              &dataOutMoved);
    if (ccStatus != kCCSuccess) {
        NSLog(@"CCCryptorFinal status: %d", ccStatus);
        CCCryptorRelease(cryptor);
        return nil;
    }
    
    CCCryptorRelease(cryptor);
    
    dataOutMovedTotal += dataOutMoved;
    dataOut.length = dataOutMovedTotal;
    
    return dataOut;
}

+ (NSString *) encrypt: (NSString *)clearText key: (NSString *)key iv: (NSString *)iv {
    NSData *result = [self AES128CBC:@"encrypt" data:[[NSData alloc] initWithBase64EncodedString:clearText options:0] key:key iv:iv];
    return [result base64EncodedStringWithOptions:0];
}

+ (NSString *) decrypt: (NSString *)cipherText key: (NSString *)key iv: (NSString *)iv {
    NSData *result = [self AES128CBC:@"decrypt" data:[[NSData alloc] initWithBase64EncodedString:cipherText options:0] key:key iv:iv];
    return [result base64EncodedStringWithOptions:0];
}

+ (NSString *) hmac256: (NSString *)input key: (NSString *)key {
    NSData *keyData = [self fromHex:key];
    NSData* inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    void* buffer = malloc(CC_SHA256_DIGEST_LENGTH);
    CCHmac(kCCHmacAlgSHA256, [keyData bytes], [keyData length], [inputData bytes], [inputData length], buffer);
    NSData *nsdata = [NSData dataWithBytesNoCopy:buffer length:CC_SHA256_DIGEST_LENGTH freeWhenDone:YES];
    return [self toHex:nsdata];
}

+ (NSString *) sha1: (NSString *)input {
    NSData* inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *result = [[NSMutableData alloc] initWithLength:CC_SHA1_DIGEST_LENGTH];
    CC_SHA1([inputData bytes], (CC_LONG)[inputData length], result.mutableBytes);
    return [self toHex:result];
}

+ (NSString *) sha256: (NSString *)input {
    NSData* inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char* buffer = malloc(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256([inputData bytes], (CC_LONG)[inputData length], buffer);
    NSData *result = [NSData dataWithBytesNoCopy:buffer length:CC_SHA256_DIGEST_LENGTH freeWhenDone:YES];
    return [self toHex:result];
}

+ (NSString *) sha512: (NSString *)input {
    NSData* inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char* buffer = malloc(CC_SHA512_DIGEST_LENGTH);
    CC_SHA512([inputData bytes], (CC_LONG)[inputData length], buffer);
    NSData *result = [NSData dataWithBytesNoCopy:buffer length:CC_SHA512_DIGEST_LENGTH freeWhenDone:YES];
    return [self toHex:result];
}

+ (NSString *) randomUuid {
  return [[NSUUID UUID] UUIDString];
}

+ (NSString *) randomKey: (NSInteger)length {
    NSMutableData *data = [NSMutableData dataWithLength:length];
    int result = SecRandomCopyBytes(kSecRandomDefault, length, data.mutableBytes);
    if (result != noErr) {
        return nil;
    }
    return [self toHex:data];
}

@end
