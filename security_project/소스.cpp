#include <sys/timeb.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define MODULUS 512
#define MAXBUFF 1024

void private_key_save(FILE* privfp, char* privfn, EVP_PKEY* pkey) { //����Ű ����
    fopen_s(&privfp, privfn, "wb");
    // privfn ������ ���̳ʸ� ������ ����� ���� ��� privfp�� �Ҵ�
    PEM_write_PKCS8PrivateKey(privfp, pkey, NULL, NULL, 0, 0, NULL);
    // PKCS # 5 V2.0 ��й�ȣ ��� ��ȣȭ �˰����� ����Ͽ� pkcs # 8 EncryptedprivatekeyInfo ������ EVP_PKEY ������ ���� Ű�� �ۼ�
    fclose(privfp);

}
void public_key_save(FILE* pubfp, char* pubfn, EVP_PKEY* pkey) //���� Ű ���� 
{
    //����Ű ����
    fopen_s(&pubfp, pubfn, "wb");
    //pubgn ������ ���̳ʸ� ������ ����� ���� ��� fp�� �Ҵ�
    PEM_write_PUBKEY(pubfp, pkey); //����Ű �ۼ� 
    //pkey���� ����Ű�� fp�� �ۼ�!
    fclose(pubfp);
}

void signature_encrypt(EVP_PKEY_CTX* ctx, EVP_PKEY* privkey, unsigned char* signature, unsigned char* plainText, size_t outlen) //����� ��ȣȭ 

{   // �� -> �ؽ��Լ� -> �޼��� ��������Ʈ -> ����Ű�� ���� -> �����м��� �� ����!
   //����� ��ȣȭ - ����Ű�� ��ȣȭ �� �ؽ� �˰��� ����

    ctx = EVP_PKEY_CTX_new(privkey, NULL);                                 //ctx ���� �� Ű ����
    // �Ķ���� Ÿ���� EVP_PKEY *, privkey�� ������ �˰����� ����Ͽ� ���� Ű �˰����� �Ҵ�
    EVP_PKEY_sign_init(ctx);                                          //ctx �ʱ�ȭ
    // �Ķ���� Ÿ���� EVP_PKEY_CTX, ���� �۾��� Ű pkey�� ����Ͽ� ���� Ű �˰��� ������ �ʱ�ȭ
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);                     //�е� ����
    // ctx�� ���� RSA �е� ��带 ����,�е����� RSA_PKCS1_PADDING�̸� flen�� PKCS #1 v1.5��� �е������ ��� RSA_size ( rsa )-11�̸� 
    EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());                        //�ؽ� �˰��� ����
    // ���� ���Ǵ� �ؽþ˰����� ����, sha256()�ؽ� �˰��� ���
    EVP_PKEY_sign(ctx, NULL, &outlen, plainText, EVP_MD_size(EVP_sha256()));      //buffer ���� ����
    // ctx�� ����Ͽ� ����Ű ���� �۾� ����, ������ ������ plainText�� sha256�� �ؽ�ũ�⸦ �Ű� ������ ����Ͽ� ����,
    //�ι�° �Ķ���Ͱ� NULL�� ���, ��� ������ �ִ�ũ�Ⱑ &outlen�Ű� ������ ���
    EVP_PKEY_sign(ctx, signature, &outlen, plainText, EVP_MD_size(EVP_sha256()));   //RSA ��ȣȭ
    // ctx�� ����Ͽ� ����Ű ���� �۾� ����, ������ ������ plainText�� sha256�� �ؽ�ũ�⸦ �Ű� ������ ����Ͽ� ����,
    //�ι�° �Ķ��Ƽ�� NULL�� �ƴ� ���, ������ signature�� ��ϵǰ� ���� ������ ũ��� outlen�� ���
    EVP_PKEY_CTX_free(ctx);

    return;
}

void create_cert(int index, X509* temp_x509, EVP_PKEY* temp_pubkey, EVP_PKEY* temp_privkey, char* temp_certFn) {

    FILE* fp = NULL;

    X509_NAME* name;
    int serial = 0;
    unsigned char* who = NULL;

    temp_x509 = X509_new();

    X509_set_version(temp_x509, 2);
    //X509�� version �Ӽ��� V03���� ����

    ASN1_INTEGER_set(X509_get_serialNumber(temp_x509), serial);
    //X509�� serialNumber �Ӽ��� ���� serial������ ����

    X509_gmtime_adj(X509_get_notBefore(temp_x509), 0);
    //X509�� notBefore �Ӽ��� ���� �ð����� ����

    X509_gmtime_adj(X509_get_notAfter(temp_x509), (long)365 * 24 * 60 * 60);
    //X509�� notAfter �Ӽ��� ���ݺ��� 365 ��* 24�ð� * 60 �� * 60 �� �ķ� ����



    X509_set_pubkey(temp_x509, temp_pubkey);
    //X509�� ����Ű�� ���� pubkey������ ����

    name = X509_get_subject_name(temp_x509);
    //X509�� X509_NAME �Ӽ��� name �Ҵ�


    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"KR", -1, -1, 0);
    //name�� MBSTRING_ASC������ C�Ӽ��� �ѱ� �����ڵ� KR�� ���� len�� -1�̹Ƿ� �Ӽ��� ���̴� ���������� ��� loc�� set������ ������ ��ġ�� �߰�

    if (index == 1) { //����� �ٸ���
        who = (unsigned char*)"Alice";
    }
    else { //����� ��
        who = (unsigned char*)"Bob";
    }
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, who, -1, -1, 0);
    //name�� MBSTRING_ASC������ O�Ӽ��� ������� �����ڷ� who�� ���� len�� -1�̹Ƿ� �Ӽ��� ���̴� ���������� ��� loc�� set������ ������ ��ġ�� �߰�

    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0);
    //name�� MBSTRING_ASC������ CN�Ӽ��� localhost�� ���� len�� -1�̹Ƿ� �Ӽ��� ���̴� ���������� ��� loc�� set������ ������ ��ġ�� �߰�

    X509_set_issuer_name(temp_x509, name);
    //������ name�� x509�� ����

    X509_sign(temp_x509, temp_privkey, EVP_sha256()); //��������� ����Ű ��� �ڽ��� ����Ű
    //privkey�� MD: sha256�� �̿��Ͽ� x509�� ����

    fopen_s(&fp, temp_certFn, "wb");
    //certFn ������ ���̳ʸ� ������ ���� ���� ��� fp�� �Ҵ�

    PEM_write_X509(fp, temp_x509);
    //fp�� ����Ű�� ���Ͽ� x509�� ���

    fclose(fp);


    X509_free(temp_x509);
    EVP_PKEY_free(temp_privkey);
    EVP_PKEY_free(temp_pubkey);

    return;
}

int x509_check(const char* certFn, X509* temp_x509) {
    FILE* fp = NULL;

    EVP_PKEY* temp_pubkey;

    fopen_s(&fp, certFn, "rb");
    PEM_read_X509(fp, &temp_x509, NULL, NULL);   //fp���� ���� x509 ������ temp_x509�� �Ҵ�
    temp_pubkey = EVP_PKEY_new();
    temp_pubkey = X509_get_pubkey(temp_x509);   //temp_x509���� pubkey�κи� temp_pubkey�� �Ҵ�


    //temp_x509�� ������ temp_pubkey�� Ȯ�� 1�� ������ �����۵�
    return  X509_verify(temp_x509, temp_pubkey);
}

EVP_PKEY* x509_pop(const char* certFn, X509* temp_x509) { //���������� ����Ű�� ���� 
    FILE* fp;

    EVP_PKEY* pubkey_x509;

    temp_x509 = X509_new();
    fopen_s(&fp, certFn, "rb");
    PEM_read_X509_AUX(fp, &temp_x509, NULL, NULL);
    fclose(fp);

    pubkey_x509 = EVP_PKEY_new();
    pubkey_x509 = X509_get_pubkey(temp_x509);

    int n = X509_verify(temp_x509, pubkey_x509);

    if (n == 1) {
        printf("���������� ����Ű ���� �Ϸ� \n\n");
    }
    else {
        printf("���������� ����Ű ���� ���� \n\n");
    }


    X509_free(temp_x509);

    return pubkey_x509;


}

void file_read(char* fn) {
    FILE* read_fp = NULL;
    char buffer[1000];

    fopen_s(&read_fp, fn, "rb"); //���̳ʸ� �б���� fn�� ���� read_fp �Ҵ�

    if (fgets(buffer, 1000, read_fp) != NULL) {
        printf("%s \n\n", buffer);
    }
    else {
        printf("���Ͽ��� ���ڿ��� ���� �� �����ϴ�. \n\n");
    }

    fclose(read_fp);


}

void set_combine(char* pfn, unsigned char* plainText, unsigned char* signature, char* Alice_certFn) {
    //before_aesE.txt�� ��ȣȭ�� �޼��� ����


    FILE* fp = NULL;

    fopen_s(&fp, pfn, "wb"); //pfn ������ ���̳ʸ� ������� ����

    //printf("�޼��� + �����м��� + �ٸ����� ����Ű ������ ��ħ : %s \n\n", text);
    //@@ ������

    fprintf(fp, "%s@@%s@@%s", plainText, signature, Alice_certFn);

    fclose(fp);

    return;

}

void set_combine2(char* finalfn, char* cfn, unsigned char* cipherText) {
    //from_Bob.txt�� �信�� ���� ���� �޼��� ����


    FILE* read_fp = NULL;
    FILE* write_fp = NULL;

    if (0 != fopen_s(&read_fp, cfn, "rb")) { //cfn ������ ���̳ʸ� �б���� ����
        printf("%s ������ ���� ���Ͽ����ϴ�. ", cfn);

        return;

    }
    char buffer[1000] = "";

    fgets(buffer, 1000, read_fp); // read_fp�� 1000 ũ�⸸ŭ ���ۿ� ����

    fopen_s(&write_fp, finalfn, "wb"); //finafn ������ ���̳ʸ� ������� ����


    fprintf(write_fp, "%s@@%s", buffer, cipherText);// from_Bob.txt�� ��ȣȭ�� �޼���+�����к��� (@@������)

    fclose(read_fp);
    fclose(write_fp);


    return;

}

void getTimeSubstr(char buff[]) {
    struct _timeb objTimeb;
    // _timeb ����ü 
    // time_t time; // time_t 970�� 1�� 1�� ����(00:00:00)(UTC(���� �����)) ������ �ð�(��)
    // unsigned short; // 1/1000��
    // short timezone; //���� ǥ�ؽÿ� �������� �м� ����
    // short dstflag; //���Ÿ�� ����� 0�� �ƴ� ��, �� �ۿ��� 0

    struct tm t;
    // tm ����ü
    // int tm_sec; ���� �ð��� �������� 0~61 
    // int tm_min; ���� �ð��� ������� 0~59
    // int tm_hour; ���� �ð��� ������� 0~23
    // int tm_mday; ������ �������� 1~31
    // int tm_mon; ������ ������� 0~11
    // int tm_year; ������ �������
    // int tm_wday; ������ ���� �������� 0~6
    // int tm_yday; 1�� 1�Ϻ��� �� ���� �������� 0~365
    // int tm_isdst; ���� Ÿ������ �ǽ��ϰ� �ִ���(1) �ƴ���(0)

    _ftime_s(&objTimeb);
    // ���� ���� �ð��� �����ͼ� objTImeb ����ü ������ ����

    localtime_s(&t, &objTimeb.time);
    // �ι�° �Ķ���Ϳ� ����� �ð��� ��ȯ�Ͽ� ù��° �Ķ���Ϳ� ����
    //�� ���� ������ ���� �ð��� ����

    //memcpy �޸� �Ϻκ� ����
    //�ι�° �Ķ���Ͱ� ����Ű�� ������ (����° �Ķ���� ��)4 ����Ʈ ��ŭ�� ù��° �Ķ���Ͱ� ����Ű�� ���� ���� 
    memcpy(buff, &(t.tm_sec), 4);
    memcpy(buff + 4, &(objTimeb.millitm), 4);

    return;
}

void create_randomKey(char seedbuff[], unsigned char mykey[], unsigned char iv[]) { //�������� Ű ����
    getTimeSubstr(seedbuff);
    RAND_seed(seedbuff, 8);  //unsigned char *buf, int num
    //seedbuff�� 8����Ʈ�� PRNG���·� ȥ��
    //PRNG���´� ����ð� ���

    int n = RAND_bytes(mykey, 64); // mykey�� byte =64
    int m = RAND_bytes(iv, 16);// iv�� byte = 16
    // ��ȣȭ������ ������ ������ �ǻ糭�� ����Ʈ�� ù��° �Ķ���Ϳ� ����
    // PRNG�� ������ ������ ����Ʈ �������� �����ϱ⿡ ����� ���Ǽ��� �ο����� ���� ��� ������ �߻�
    // �����ϸ� 1, �׷��� ������ 0 ��ȯ

    if (n == 1 && m == 1) {
        printf("��ĪŰ: %s \n", mykey);
        printf("�ʱ⺤��: %s \n\n", iv);
    }
    return;

}

int AES_encryption(char* pfn, char* cfn, unsigned char* mykey, unsigned char* iv) {
    FILE* ptf, * ctf;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int in_len, out_len = 0, ret;
    unsigned char ptext[MAXBUFF + 8];
    unsigned char ctext[MAXBUFF + 8];

    fopen_s(&ptf, pfn, "rb");
    // pfn ������ ���̳ʸ� ������ �б� ���� ��� ptf�� �Ҵ�
    fopen_s(&ctf, cfn, "wb");
    // cfn ������ ���̳ʸ� ������ ���� ���� ��� ctf�� �Ҵ�
    //EVP_CIPHER_CTX_init(ctx);
    // ��ȣ ���ؽ� ctx�� �ʱ�ȭ�Ѵ�



    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, 1);
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, mykey, iv, AES_ENCRYPT);
    // ��ȣȭ�� ���� ��ȣ ���ؽ�Ʈ ctx�� ���� , ctx�� �ʱ�ȭ, ��ȣȭ ���� EVP_aes_128_cbc , impl�� NULL�� �ʱ�ȭ,
    // ��ĪŰ�� mykey, CBC����� �ʱ� ���� = iv, AES_ENCRYPT��ȣ flag 1�ϰ�� ��ȣȭ, 0�ϰ�� ��ȣȭ

    while ((in_len = fread(ptext, 1, MAXBUFF, ptf)) > 0) {
        //ptf���� MAXBUFF���� ���Ҹ� ������ �迭�� �о�´�. �� ������ ũ��� 1����Ʈ�̰� ptext�� ����Ű�� �迭�� �ְԵȴ�.
        ret = EVP_CipherUpdate(ctx, ctext, &out_len, ptext, in_len);
        // ��ȣȭ ���� , ctext = ��ȣ�� �����Ͱ� ����� ����, out_len = ��ȣ�� ������ ����Ʈ�� ũ��, ptext = ��ȣȭ ��, in_len = ��ȣȭ �� ����
        fwrite(ctext, 1, out_len, ctf);
        //ctext�� �����͸� ctf�� ����Ű�� ���Ͽ� ����, 1�� ������� �������� ����ũ��(����Ʈ), out_len�� ������ ���� ����

        printf("AES��ȣȭ �� �������� ����: %d \n", in_len);
    }


    fclose(ptf);
    ret = EVP_CipherFinal_ex(ctx, ctext, &out_len);
    // ��ȣȭ ��� ����, ctext = ��ȣ�� �����Ͱ� ����� ����, out_len = ��ȣ�� �������� ���̰� ����
    printf("AES��ȣȭ �� �������� ����: %d \n", out_len);
    fwrite(ctext, 1, out_len, ctf);
    fclose(ctf);
    EVP_CIPHER_CTX_cleanup(ctx);

    return out_len;
}

void RSA_encryption(EVP_PKEY_CTX* ctx, unsigned char mykey[], EVP_PKEY* pubkey, size_t outlen, unsigned char* cipherText) {
    //��ȣȭ - ��ĪŰ(mykey)�� ���� ����Ű(pubkey)�� ��ȣȭ

    ctx = EVP_PKEY_CTX_new(pubkey, NULL);                           //ctx ���� �� Ű ����
    // �Ķ���� Ÿ���� EVP_PKEY_CTX, ����Ű �˰����� ����Ű �Ҵ�
    EVP_PKEY_encrypt_init(ctx);                                    //ctx �ʱ�ȭ
    // �Ķ���� Ÿ���� EVP_PKEY_CTX, ��ȣ �۾��� Ű pkey�� ����Ͽ� ���� Ű �˰��� ������ �ʱ�ȭ
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING);                  //�е� ����
    // ctx�� ���� RSA �е� ��带 ����,�е����� RSA_NO_PADDING
    EVP_PKEY_encrypt(ctx, NULL, &outlen, mykey, MODULUS / 8);         //buffer ���� ����
    // ctx�� ����Ͽ� ����Ű ��ȣ �۾� buffer���� ����, ��ȣȭ�� ������ plainText�� MODULUS / 8�� ũ�⸦ �Ű� ������ ����Ͽ� ����,
    //NULL�ΰ�� ��� ������ �ִ�ũ�Ⱑ &outlen�ŰԺ����� ���
    EVP_PKEY_encrypt(ctx, cipherText, &outlen, mykey, MODULUS / 8);      //RSA ��ȣȭ
    // ctx�� ����Ͽ� ����Ű ��ȣȭ �۾� ����, ��ȣȭ�� ������ plainText�� MODULUS / 8 ũ�⸦ �Ű� ������ ����Ͽ� ����,
    // ��ȣ��(cipherText) ������ ũ�Ⱑ &outlen�ŰԺ����� ���
    EVP_PKEY_CTX_free(ctx);

    printf("RSA ��ȣȭ �� ������ ������ ����: %d \n", outlen);

}

void RSA_decryption(char* pfn, unsigned char* encrypted, unsigned char* decrypted, int _public) //pfn ������ �Է� �޾� ��ȣȭ
{   //encrypted == ciperText
   //decrypted == mykey

    EVP_PKEY* _pkey = NULL;
    FILE* pfp = NULL;

    if (!_public) //����Ű�� �̰����� ����Ű �������� ���� ����
    {
        //����Ű ����
        fopen_s(&pfp, pfn, "wb");
        PEM_write_PKCS8PrivateKey(pfp, _pkey, NULL, NULL, 0, 0, NULL);
        fclose(pfp);

        //����Ű �ε�
        fopen_s(&pfp, pfn, "rb");
        PEM_read_PrivateKey(pfp, &_pkey, 0, NULL);
        fclose(pfp);
    }
    else //����Ű�� �̰����� ����Ű �������� ���� ����
    {
        //����Ű ����
        fopen_s(&pfp, pfn, "wb");
        PEM_write_PUBKEY(pfp, _pkey);
        fclose(pfp);

        //����Ű �ε�
        fopen_s(&pfp, pfn, "rb");
        PEM_read_PUBKEY(pfp, &_pkey, 0, NULL);
        fclose(pfp);
    }

    size_t outlen = 0;
    int result = 0;
    EVP_PKEY_CTX* ctx = NULL;
    ctx = EVP_PKEY_CTX_new(_pkey, NULL);                           //ctx ���� �� Ű ����
    // �Ķ���� Ÿ���� EVP_PKEY, ����Ű �˰����� ����Ű �Ҵ�
    EVP_PKEY_decrypt_init(ctx);                                    //ctx �ʱ�ȭ
    // �Ķ���� Ÿ���� EVP_PKEY_CTX,  ��ȣȭ �۾��� Ű pkey�� ����Ͽ� ���� Ű �˰��� ���븦 �ʱ�ȭ�Ѵ�.
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING);                  //�е� ����
    // ctx�� ���� RSA �е� ��带 ����,�е����� RSA_NO_PADDING
    EVP_PKEY_decrypt(ctx, NULL, &outlen, encrypted, outlen);            //buffer ���� ����
    // ctx�� ����Ͽ� ����Ű ��ȣ �۾� buffer���� ����, ��ȣȭ�� ������ encrypted�� outlen�� ũ�⸦ �Ű� ������ ����Ͽ� ����,
    // NULL�ΰ�� ��� ������ �ִ�ũ�Ⱑ &outlen �Ű������� ���
    result = EVP_PKEY_decrypt(ctx, decrypted, &outlen, encrypted, outlen);      //RSA ��ȣȭ
    //ctx�� ����Ͽ� ����Ű ��ȣȭ �۾� ����, ��ȣȭ�� ������ encrypted�� otlen�� ũ�⸦ �Ű� ������ ����Ͽ� ����,
    //����(decrypted) ������ ũ�Ⱑ &outlen �Ű������� ���

    EVP_PKEY_CTX_free(ctx);
}

void AES_decryption(char* cfn, char* dfn, unsigned char mykey[], unsigned char iv[]) {  //AES ��ȣȭ
    FILE* ctf, * dtf;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int in_len, out_len = 0, ret;
    unsigned char ctext[MAXBUFF + 8];
    unsigned char dtext[MAXBUFF + 16];

    fopen_s(&ctf, cfn, "rb");
    // cfn ������ ���̳ʸ� ������ �б� ���� ��� ctf �� �Ҵ�
    fopen_s(&dtf, dfn, "wb");
    // dfn ������ ���̳ʸ� ������ ���� ���� ��� dtf�� �Ҵ�

    // ��ȣ ���ؽ� ctx�� �ʱ�ȭ�Ѵ�
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, 1);
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, mykey, iv, AES_DECRYPT);
    // ��ȣȭ�� ���� ��ȣ ���ؽ�Ʈ ctx�� ���� , ctx�� �ʱ�ȭ, ��ȣȭ ���� EVP_aes_128_cbc , impl�� NULL�� �ʱ�ȭ,
    // ��ĪŰ�� mykey, CBC����� �ʱ� ���� = iv, AES_ENCRYPT��ȣ flag 1�ϰ�� ��ȣȭ
    while ((in_len = fread(ctext, 1, MAXBUFF, ctf)) > 0) {
        // ctf���� MAXBUFF���� ���Ҹ� ������ �迭�� �о�´�. �� ������ ũ��� 1����Ʈ�̰� Ctext�� ����Ű�� �迭�� �ְԵȴ�.
        ret = EVP_CipherUpdate(ctx, dtext, &out_len, ctext, in_len);
        // ��ȣȭ ���� , dtext = ��ȣ�� �����Ͱ� ����� ����, out_len = ��ȣ�� ������ ����Ʈ�� ũ��, dtext = ��ȣȭ�� ��, in_len = ��ȣȭ�� �� ����
        fwrite(dtext, 1, out_len, dtf);
        //dtext�� �����͸� dtf�� ����Ű�� ���Ͽ� ����, 1�� ���������� ����ũ��(����Ʈ), out_len�� ������ ���� ����
    }
    fclose(ctf);
    ret = EVP_CipherFinal_ex(ctx, dtext, &out_len);
    // ��ȣȭ ��� ����, dtext = ��ȣ�� �����Ͱ� ����� ����, out_len = ��ȣ�� �������� ���̰� ����
    fwrite(dtext, 1, out_len, dtf);

    fclose(dtf);
    EVP_CIPHER_CTX_cleanup(ctx);
}



//�и��� ����, ��ȣȭ�� �޼��� ũ��, �����к��� ũ��, �и��� ��ȣȭ�� �޼���, �и��� ������ ����
void set_Divide(char* finalfn, char* cfn, unsigned char* cipherText)
{
    FILE* read_fp = NULL;

    char buffer[1000] = "";

    fopen_s(&read_fp, finalfn, "rb"); //���̳ʸ� �б���� finalfn�� ���� read_fp �Ҵ�
    fgets(buffer, 1000, read_fp); //read_fp ���� ������ buffer�� ����


    char* ptr = strtok(buffer, "@@");

    ptr = strtok(NULL, "@");

    fclose(read_fp);

}

void set_Divide2(char* pfn, unsigned char* plainText, unsigned char* signature, char* Alice_certFn) //�޽���, ������, �������� ������
{
    FILE* read_fp = NULL;

    char buffer[1000] = "";

    fopen_s(&read_fp, pfn, "rb"); //���̳ʸ� �б���� pfn�� ���� read_fp �Ҵ�
    fgets(buffer, 1000, read_fp); //read_fp ���� ������ buffer�� ����

    //������(@@)�� �и��ϱ� 
    char* ptr = strtok(buffer, "@@");
    plainText = (unsigned char*)ptr;

    ptr = strtok(NULL, "@");
    signature = (unsigned char*)ptr;

    ptr = strtok(NULL, "@");
    Alice_certFn = (char*)ptr;


    printf("�и��� plaintext: %s \n", plainText);
    printf("�и��� signature: %s \n", signature);
    printf("�и��� �ٸ����� ����Ű ������: %s \n\n", Alice_certFn);

    return;
}

// pubkey : ������ ����Ű
// signature : ������ ����
// plainText : ��ȣȭ�� �޽���
// ���� ���� 1�� �� ���� ���� ���, �� �� ����
int signature_decrypt(EVP_PKEY* pubkey, unsigned char* signature, unsigned char* plainText, size_t outlen) // ����� ��ȣȭ
{
    //������ ��ȣȭ - ����Ű�� ��ȣȭ �� �ؽ� �˰��� ����
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubkey, NULL);                                 //ctx ���� �� Ű ����
    // �Ķ���� Ÿ���� EVP_PKEY, ����Ű �˰����� ����Ű �Ҵ�
    EVP_PKEY_verify_init(ctx);                                          //ctx �ʱ�ȭ
    // �Ķ���� Ÿ���� EVP_PKEY_CTX, ���� ��ȣȭ �۾��� Ű pkey�� ����Ͽ� ���� Ű �˰��� ���븦 �ʱ�ȭ�Ѵ�.
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);                     //�е� ����
    // ctx�� ���� RSA �е� ��带 ����,�е����� RSA_PKCS1_PADDING�̸� flen�� PKCS #1 v1.5��� �е������ ��� RSA_size ( rsa )-11�̸�
    EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());                        //�ؽ� �˰��� ����
    // ����ȣȭ�� ���Ǵ� �ؽþ˰����� ����, sha256()�ؽ� �˰��� ���
    int result = EVP_PKEY_verify(ctx, signature, outlen, plainText, EVP_MD_size(EVP_sha256()));//RSA ��ȣȭ
    // ����� ctx�� ����Ͽ� ����Ű ����ȣȭ �۾� ����, ������ ������ plainText�� sha256�� �ؽ�ũ�⸦ �Ű� ������ ����Ͽ� ����,
    // ���� ������ ũ�Ⱑ outlen �Ű������� ���

    EVP_PKEY_CTX_free(ctx);

    return result;


}

// ************************************** main ***********************************************
int main() {

    EVP_PKEY_CTX* ctx = NULL;  // ����Ű �˰����� ����ִ� ����ü

    unsigned char* plainText = (unsigned char*)"Hello RSA"; //��

    printf("plainText: %s \n\n", plainText);

    printf("--------------------------------------------------------\n\n");

    // ********************** Ű �� ������ ����ϴ� ���� **********************
    //privkey(����Ű), pubkey(����Ű)
    size_t outlen_signatureE = 0, result = 0;
    //�ٸ���
    EVP_PKEY* Alice_pkey = NULL, * Alice_privkey = NULL, * Alice_pubkey = NULL;
    FILE* Alice_privfp = NULL, * Alice_pubfp = NULL;
    char* Alice_privfn = (char*)"Alice_privateKey.pem";
    char* Alice_pubfn = (char*)"Alice_publicKey.pem";
    //�� 
    EVP_PKEY* Bob_pkey = NULL, * Bob_privkey = NULL, * Bob_pubkey = NULL;
    FILE* Bob_privfp = NULL, * Bob_pubfp = NULL;
    char* Bob_privfn = (char*)"Bob_privateKey.pem";
    char* Bob_pubfn = (char*)"Bob_publicKey.pem";


    // ********************** ������ ����� ����ϴ� ���� **********************
    unsigned char* signature; //������ �� ����
    signature = (unsigned char*)calloc(1, MODULUS + EVP_MAX_BLOCK_LENGTH);   //����� Modulus ���� Ŭ ���� �ִ�
    //1 ũ���� ������  MODULUS + EVP_MAX_BLOCK_LENGTH�� ��ŭ ������ �� �ִ� �޸� ���� �Ҵ�


    // ********************** ������ ������ ����ϴ� ���� **********************
    // �ٸ��� 
    X509* Alice_x509 = NULL; // ������ 
    char* Alice_certFn = (char*)"Alice_Cert.der"; //������ ����
    //��
    X509* Bob_x509 = NULL;//������
    char* Bob_certFn = (char*)"Bob_Cert.der"; //������ ����


    // ********************** AES ��ȣȭ�� ����ϴ� ���� **********************
    char seedbuff[MAXBUFF] = ""; // seedbuff = 1024(MAXBUFF)
    unsigned char mykey[EVP_MAX_KEY_LENGTH] = "\0"; // mykey = 64����Ʈ(EVP_MAX_KEY_LENGTH) ��ĪŰ(����Ű)
    unsigned char iv[EVP_MAX_IV_LENGTH] = "\0"; // iv = 16����Ʈ(EVP_MAX_IV_LENGTH) �ִ��ũ��
    char* pfn = (char*)"before_aesE.txt"; //��ȣȭ �� �޼����� ��� ���� �̸�
    char* cfn = (char*)"after_aesE.txt"; // ��ȣȭ �� �޼����� ��� ���� �̸�
    int outlen_aesE = 0; //aes ��ȣȭ �� �������� ũ��





    // ********************** RSA ��ȣȭ�� ����ϴ� ���� **********************
    EVP_PKEY* Bob_pubkey_x509; //���������� ������ ���� ����Ű
    size_t outlen_rsaE = 0; //��ȣ��(cipherText) ������ ũ�Ⱑ outlen�ŰԺ����� ���
    unsigned char* cipherText; //�����к���
    cipherText = (unsigned char*)calloc(1, MODULUS + EVP_MAX_BLOCK_LENGTH);
    int rsa_out_len = 0; //rsa ��ȣȭ �� �������� ũ�� = �����к����� ũ��


    // ********************** �ٸ��� ----> �� ���� ���� **********************
    char* finalfn = (char*)"from_Bob.txt";


    // ********************** RSA ��ȣȭ�� ����ϴ� ���� **********************
    unsigned char* cipherText2; //�����к���
    cipherText2 = (unsigned char*)calloc(1, MODULUS + EVP_MAX_BLOCK_LENGTH);


    //��� �˰��� ���
    OpenSSL_add_all_algorithms();
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);




    // ********************** �ٸ��� Ű ���� **********************
    printf("E1. �ٸ��� Ű�� �����մϴ�. \n\n");
    printf("�ٸ��� ���Ű ���� �̸�: %s \n", Alice_privfn);
    printf("�ٸ��� ����Ű ���� �̸�: %s \n\n", Alice_pubfn);

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);      //ctx ����
    //ù��° �Ķ���� Ÿ���� EVP_PKEY, RSA ����Ű �˰��� �Ҵ�
    EVP_PKEY_keygen_init(ctx);                     //ctx �ʱ�ȭ
    // �ĸ����� Ÿ���� EVP_PKEY_CTX, Ű ���� ���ۿ� Ű pkey�� ����Ͽ� ����Ű �˰��� ������ �ʱ�ȭ
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, MODULUS);      //Ű ���� ����
    // Ű ���� =512
    EVP_PKEY_keygen(ctx, &Alice_pkey);                  //Ű ����
    // Ű ���� �۾��� �����ϴ� �Լ��̸� ������ Ű�� pkey�� ���
    EVP_PKEY_CTX_free(ctx);                        //ctx ��ȯ


    private_key_save(Alice_privfp, Alice_privfn, Alice_pkey); //����Ű ����
    public_key_save(Alice_pubfp, Alice_pubfn, Alice_pkey); //���� Ű ����

    //���� Ű �ε� => �Լ� �ν� ����

    fopen_s(&Alice_privfp, Alice_privfn, "rb");
    // prvifn ������ ���̳ʸ� ������ �б� ���� ��� pevfp�� �Ҵ�
    PEM_read_PrivateKey(Alice_privfp, &Alice_privkey, 0, NULL);
    fclose(Alice_privfp);

    //����Ű �ε� => �Լ� �ν� ����

    fopen_s(&Alice_pubfp, Alice_pubfn, "rb");
    // pubfn ������ ���̳ʸ� ������ �б� ���� ��� pubfp�� �Ҵ�
    PEM_read_PUBKEY(Alice_pubfp, &Alice_pubkey, 0, NULL);
    fclose(Alice_pubfp);

    if (Alice_privkey != NULL && Alice_pubkey != NULL) {

        printf("�ٸ��� Ű(����Ű, ����Ű) ���� �Ϸ� \n\n");
    }



    printf("--------------------------------------------------------\n\n");



    // ********************** �� Ű ���� **********************
    printf("E2. �� Ű�� �����մϴ�. \n\n");

    printf("�� ���Ű ���� �̸�: %s \n", Bob_privfn);
    printf("�� ����Ű ���� �̸�: %s \n\n", Bob_pubfn);

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);      //ctx ����
    //ù��° �Ķ���� Ÿ���� EVP_PKEY, RSA ����Ű �˰��� �Ҵ�
    EVP_PKEY_keygen_init(ctx);                     //ctx �ʱ�ȭ
    // �ĸ����� Ÿ���� EVP_PKEY_CTX, Ű ���� ���ۿ� Ű pkey�� ����Ͽ� ����Ű �˰��� ������ �ʱ�ȭ
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, MODULUS);      //Ű ���� ����
    // Ű ���� =512
    EVP_PKEY_keygen(ctx, &Bob_pkey);                  //Ű ����
    // Ű ���� �۾��� �����ϴ� �Լ��̸� ������ Ű�� pkey�� ���
    EVP_PKEY_CTX_free(ctx);                        //ctx ��ȯ


    private_key_save(Bob_privfp, Bob_privfn, Bob_pkey); //����Ű ����
    public_key_save(Bob_pubfp, Bob_pubfn, Bob_pkey); //���� Ű ����

    //���� Ű �ε� => �Լ� �ν� ����

    fopen_s(&Bob_privfp, Bob_privfn, "rb");
    // prvifn ������ ���̳ʸ� ������ �б� ���� ��� privfp�� �Ҵ�
    PEM_read_PrivateKey(Bob_privfp, &Bob_privkey, 0, NULL);
    fclose(Bob_privfp);

    //����Ű �ε� => �Լ� �ν� ����

    fopen_s(&Bob_pubfp, Bob_pubfn, "rb");
    // pubfn ������ ���̳ʸ� ������ �б� ���� ��� pubfp�� �Ҵ�
    PEM_read_PUBKEY(Bob_pubfp, &Bob_pubkey, 0, NULL);
    fclose(Bob_pubfp);

    if (Bob_privkey != NULL && Bob_pubkey != NULL) {

        printf("�� Ű(����Ű, ����Ű) ���� �Ϸ� \n\n");
    }

    printf("--------------------------------------------------------\n\n");

    // ********************** ����� ��ȣȭ ********************** 
    printf("E3. ���� ��ȣȭ�� �����մϴ�. \n\n");
    printf("�ؽ� �Լ�: SHA-256 \n");
    signature_encrypt(ctx, Alice_privkey, signature, plainText, outlen_signatureE);
    printf("signature: %s \n\n", signature);

    printf("--------------------------------------------------------\n\n");

    // ********************** �ٸ��� ������ ���� **********************
    printf("E4. �ٸ��� �������� �����մϴ�. \n\n");
    printf("�ٸ��� ������ ���� �̸�: %s \n\n", Alice_certFn);

    create_cert(1, Alice_x509, Alice_pubkey, Alice_privkey, Alice_certFn);
    EVP_PKEY_free(Alice_pkey);

    if (x509_check(Alice_certFn, Alice_x509)) {
        //Alice_x509�� ������ Alice_pubkey�� Ȯ��, 1�� ������ �����۵�
        printf("�ٸ��� ������ ���� �Ϸ� \n\n");
    }
    printf("--------------------------------------------------------\n\n");

    // ********************** �� ������ ���� **********************
    printf("E5. �� �������� �����մϴ�. \n\n");

    printf("�� ������ ���� �̸�: %s \n\n", Bob_certFn);

    create_cert(2, Bob_x509, Bob_pubkey, Bob_privkey, Bob_certFn);
    EVP_PKEY_free(Bob_pkey);


    if (x509_check(Bob_certFn, Bob_x509)) {
        //Bob_x509�� ������ Bob_pubkey�� Ȯ��, 1�� ������ �����۵�
        printf("�� ������ ���� �Ϸ� \n\n");
    }
    printf("--------------------------------------------------------\n\n");


    // ********************** �޼��� + �����м��� + �ٸ�������Ű������ ��ġ��**********************
    printf("E6. �޼��� + �����м��� + �ٸ�������Ű������ ������ �����մϴ�. \n\n");
    printf("���� �̸�: %s \n", pfn);
    set_combine(pfn, plainText, signature, Alice_certFn);
    //before_aesE.txt�� ��ȣȭ�� �޼��� ����
    printf("���� ����: "); file_read(pfn);
    printf("--------------------------------------------------------\n\n");

    // ********************** ��ĪŰ�� IV ���� **********************
    printf("E7. ��ĪŰ�� �ʱ⺤��(IV)�� �����մϴ�. \n\n");
    create_randomKey(seedbuff, mykey, iv); //�ǻ糭�� ������� Ű ���� => ��ĪŰ
    printf("--------------------------------------------------------\n\n");

    // ********************** AES ��ȣȭ **********************
    printf("E8. AES ��ȣȭ�� �����մϴ�. \n\n");
    printf("AES ��ȣȭ �˰���: AES-128-CBC \n");
    outlen_aesE = AES_encryption(pfn, cfn, mykey, iv); //AES ��ĪŰ ��ȣȭ

    printf("���� �̸�: %s \n", cfn);
    printf("��ȣȭ�� ���� ����: "); file_read(cfn);
    printf("--------------------------------------------------------\n\n");



    // ********************** �� ���������� ����Ű ���� **********************
    printf("E9. �� ���������� ����Ű�� �����մϴ�. \n\n");

    X509* root_x509 = NULL;
    FILE* fp = NULL;

    printf("���� ������ ���� �̸�: %s \n", Alice_certFn);
    Bob_pubkey_x509 = x509_pop(Bob_certFn, root_x509);


    printf("--------------------------------------------------------\n\n");

    // ********************** RSA ��ȣȭ **********************
    printf("E10. RSA ��ȣȭ�� �����մϴ�. \n\n");
    RSA_encryption(ctx, mykey, Bob_pubkey_x509, outlen_rsaE, cipherText);
    printf("cipherText : %s \n\n", cipherText);

    printf("--------------------------------------------------------\n\n");

    // ********************** ��ȣȭ�� �޼��� + �����к��� ��ġ��**********************
    printf("E11. ��ȣȭ�� �޼��� + �����к��� ������ �����մϴ�. \n\n");
    set_combine2(finalfn, cfn, cipherText);
    printf("���� �̸�: %s \n", finalfn);
    printf("���� ����: "); file_read(finalfn); //finalfn�� ���� ���

    printf("--------------------------------------------------------\n\n");
    printf("--------------------------------------------------------\n\n");
    printf("--------------------------------------------------------\n\n");

    // ********************** ��ȣȭ�� �޼���, �����к��� �и��ϱ�**********************
    printf("D1. ������ ��ȣȭ�� �޼���, �����к��� ���Ϸ� �и��մϴ�. \n\n");
    char* cfn2 = (char*)"before_aesD"; //�и��� ��ȣȭ�� �޼��� ����

    set_Divide(finalfn, cfn2, cipherText2);
    //�и��� ����, �и��� ��ȣȭ�� �޼���, �и��� ������ ����

    printf("cipherText: %s \n", cipherText);
    printf("��ȣȭ�� �޼���: "); file_read(cfn);

    printf("--------------------------------------------------------\n\n");





    // ********************** RSA ��ȣȭ **********************
    printf("D2. RSA ��ȣȭ�� �����մϴ�. \n\n");
    //RSA_decryption(char* pfn, unsigned char* encrypted, unsigned char* decrypted, int _public)
    printf("��ȣȭ �ϱ� �� cipherText: %s \n", cipherText);
    RSA_decryption(Bob_privfn, cipherText, mykey, 1); //Bob�� ����Ű�� ������ ������ ���� mykey�� ��ĪŰ ����
    printf("��ȣȭ�� ���� ��Ī Ű: %s \n\n", mykey);
    printf("--------------------------------------------------------\n\n");


    // ********************** AES ��ȣȭ **********************

    char* dfn = (char*)"after_aesD.txt"; //��ȣȭ �� �޼����� ��� ����

    printf("D3. AES ��ȣȭ�� �����մϴ�. \n\n");
    printf("��ȣȭ�ϱ� �� �޼���: "); file_read(cfn);
    //AES_decryption(char* cfn, char* dfn, unsigned char mykey[], unsigned char iv[])
    AES_decryption(cfn, dfn, mykey, iv);

    printf("AES ��ȣȭ �˰���: AES-128-CBC \n");
    printf("��ȣȭ�� ��� ���� �̸�: %s \n", dfn);
    printf("��ȣȭ�� ���� ���� ����: ");  file_read(dfn);

    printf("--------------------------------------------------------\n\n");


    // ********************** �޼���, �����м���, �ٸ�������Ű������ �и��ϱ�**********************
    printf("D4. ������ �޼���, �����м���, �ٸ�������Ű�������� �и��մϴ�. \n\n");

    unsigned char* plainText2 = NULL; //�и��Ͽ� �޼��� ����
    unsigned char* signature2; //�и��Ͽ� ������ �� ����
    signature2 = (unsigned char*)calloc(1, MODULUS + EVP_MAX_BLOCK_LENGTH);   //����� Modulus ���� Ŭ ���� �ִ�
    //1 ũ���� ������  MODULUS + EVP_MAX_BLOCK_LENGTH�� ��ŭ ������ �� �ִ� �޸� ���� �Ҵ�
    char* Alice_certFn2 = NULL; //�и��Ͽ� �ٸ�������Ű������ ����

    printf("�и��� ���� �̸�: %s \n", dfn);

    set_Divide2(dfn, plainText2, signature2, Alice_certFn2);

    printf("--------------------------------------------------------\n\n");

    // ********************** �ٸ��� ���������� ����Ű ���� **********************
    printf("D5. �ٸ��� ���������� ����Ű�� �����մϴ�. \n\n");

    root_x509 = NULL;
    EVP_PKEY* Alice_pubkey_x509; //���������� ������ �ٸ����� ����Ű

    printf("�ٸ����� ������ ���� �̸�: %s \n", Alice_certFn);
    Alice_pubkey_x509 = x509_pop(Alice_certFn, root_x509);


    printf("--------------------------------------------------------\n\n");

    // ********************** ����� ��ȣȭ **********************
    printf("D6. ����� ��ȣȭ �� �޼��� ��������Ʈ�� ���մϴ�. \n\n");
    printf("�ؽ��Լ�: SHA-256 \n\n");
    int result_S = signature_decrypt(Alice_pubkey_x509, signature, plainText, outlen_signatureE);
    printf("plain text: %s\n", plainText);
    printf("signature: %s\n", signature);
    printf("result: %d\n", result_S);

    printf("--------------------------------------------------------\n\n");


    getchar();
    return 0;
}