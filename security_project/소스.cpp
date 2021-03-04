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

void private_key_save(FILE* privfp, char* privfn, EVP_PKEY* pkey) { //개인키 저장
    fopen_s(&privfp, privfn, "wb");
    // privfn 파일을 바이너리 형식의 덮어쓰기 모드로 열어서 privfp에 할당
    PEM_write_PKCS8PrivateKey(privfp, pkey, NULL, NULL, 0, 0, NULL);
    // PKCS # 5 V2.0 비밀번호 기반 암호화 알고리즘을 사용하여 pkcs # 8 EncryptedprivatekeyInfo 형식의 EVP_PKEY 구조로 개인 키를 작성
    fclose(privfp);

}
void public_key_save(FILE* pubfp, char* pubfn, EVP_PKEY* pkey) //공개 키 저장 
{
    //공개키 저장
    fopen_s(&pubfp, pubfn, "wb");
    //pubgn 파일을 바이너리 형식의 덮어쓰기 모드로 열어서 fp에 할당
    PEM_write_PUBKEY(pubfp, pkey); //공개키 작성 
    //pkey에서 공개키를 fp에 작성!
    fclose(pubfp);
}

void signature_encrypt(EVP_PKEY_CTX* ctx, EVP_PKEY* privkey, unsigned char* signature, unsigned char* plainText, size_t outlen) //서명용 암호화 

{   // 평문 -> 해시함수 -> 메세지 다이제스트 -> 개인키로 서명 -> 디지털서명 값 생성!
   //서명용 암호화 - 개인키로 암호화 및 해시 알고리즘 지정

    ctx = EVP_PKEY_CTX_new(privkey, NULL);                                 //ctx 생성 및 키 설정
    // 파라미터 타입은 EVP_PKEY *, privkey에 지정된 알고리즘을 사용하여 공개 키 알고리즘을 할당
    EVP_PKEY_sign_init(ctx);                                          //ctx 초기화
    // 파라미터 타입은 EVP_PKEY_CTX, 서명 작업에 키 pkey를 사용하여 공개 키 알고리즘 내용을 초기화
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);                     //패딩 설정
    // ctx에 대한 RSA 패딩 모드를 설정,패딩모드는 RSA_PKCS1_PADDING이며 flen은 PKCS #1 v1.5기반 패딩모드의 경우 RSA_size ( rsa )-11미만 
    EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());                        //해시 알고리즘 설정
    // 서명에 사용되는 해시알고리즘을 설정, sha256()해시 알고리즘 사용
    EVP_PKEY_sign(ctx, NULL, &outlen, plainText, EVP_MD_size(EVP_sha256()));      //buffer 길이 결정
    // ctx를 사용하여 공개키 서명 작업 수행, 서명할 데이터 plainText및 sha256의 해시크기를 매개 변수를 사용하여 지정,
    //두번째 파라미터가 NULL인 경우, 출력 버퍼의 최대크기가 &outlen매개 변수에 기록
    EVP_PKEY_sign(ctx, signature, &outlen, plainText, EVP_MD_size(EVP_sha256()));   //RSA 암호화
    // ctx를 사용하여 공개키 서명 작업 수행, 서명할 데이터 plainText및 sha256의 해시크기를 매겨 변수를 사용하여 지정,
    //두번째 파라미티거 NULL이 아닌 경우, 서명은 signature에 기록되고 서명 버퍼의 크기는 outlen에 기록
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
    //X509의 version 속성을 V03으로 설정

    ASN1_INTEGER_set(X509_get_serialNumber(temp_x509), serial);
    //X509의 serialNumber 속성을 변수 serial값으로 설정

    X509_gmtime_adj(X509_get_notBefore(temp_x509), 0);
    //X509의 notBefore 속성을 현재 시간으로 설정

    X509_gmtime_adj(X509_get_notAfter(temp_x509), (long)365 * 24 * 60 * 60);
    //X509의 notAfter 속성을 지금부터 365 일* 24시간 * 60 분 * 60 초 후로 설정



    X509_set_pubkey(temp_x509, temp_pubkey);
    //X509의 공개키를 변수 pubkey값으로 설정

    name = X509_get_subject_name(temp_x509);
    //X509의 X509_NAME 속성을 name 할당


    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"KR", -1, -1, 0);
    //name의 MBSTRING_ASC유형의 C속성에 한국 국가코드 KR로 설정 len이 -1이므로 속성의 길이는 내부적으로 계산 loc과 set에의해 결정된 위치에 추가

    if (index == 1) { //기업명 앨리스
        who = (unsigned char*)"Alice";
    }
    else { //기업명 밥
        who = (unsigned char*)"Bob";
    }
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, who, -1, -1, 0);
    //name의 MBSTRING_ASC유형의 O속성에 기업명을 발행자로 who로 설정 len이 -1이므로 속성의 길이는 내부적으로 계산 loc과 set에의해 결정된 위치에 추가

    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0);
    //name의 MBSTRING_ASC유형의 CN속성에 localhost로 설정 len이 -1이므로 속성의 길이는 내부적으로 계산 loc과 set에의해 결정된 위치에 추가

    X509_set_issuer_name(temp_x509, name);
    //설정된 name을 x509에 적용

    X509_sign(temp_x509, temp_privkey, EVP_sha256()); //인증기관의 개인키 대신 자신의 개인키
    //privkey와 MD: sha256를 이용하여 x509에 서명

    fopen_s(&fp, temp_certFn, "wb");
    //certFn 파일을 바이너리 형식의 쓰기 모드로 열어서 fp에 할당

    PEM_write_X509(fp, temp_x509);
    //fp가 가리키는 파일에 x509를 기록

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
    PEM_read_X509(fp, &temp_x509, NULL, NULL);   //fp에서 읽은 x509 정보를 temp_x509에 할당
    temp_pubkey = EVP_PKEY_new();
    temp_pubkey = X509_get_pubkey(temp_x509);   //temp_x509에서 pubkey부분만 temp_pubkey에 할당


    //temp_x509의 서명을 temp_pubkey로 확인 1이 나오면 정상작동
    return  X509_verify(temp_x509, temp_pubkey);
}

EVP_PKEY* x509_pop(const char* certFn, X509* temp_x509) { //인증서에서 공개키를 추출 
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
        printf("인증서에서 공개키 추출 완료 \n\n");
    }
    else {
        printf("인증서에서 공개키 추출 실패 \n\n");
    }


    X509_free(temp_x509);

    return pubkey_x509;


}

void file_read(char* fn) {
    FILE* read_fp = NULL;
    char buffer[1000];

    fopen_s(&read_fp, fn, "rb"); //바이너리 읽기모드로 fn을 열어 read_fp 할당

    if (fgets(buffer, 1000, read_fp) != NULL) {
        printf("%s \n\n", buffer);
    }
    else {
        printf("파일에서 문자열을 읽을 수 없습니다. \n\n");
    }

    fclose(read_fp);


}

void set_combine(char* pfn, unsigned char* plainText, unsigned char* signature, char* Alice_certFn) {
    //before_aesE.txt에 암호화할 메세지 쓰기


    FILE* fp = NULL;

    fopen_s(&fp, pfn, "wb"); //pfn 파일을 바이너리 쓰기모드로 열기

    //printf("메세지 + 디지털서명 + 앨리스의 공개키 인증서 합침 : %s \n\n", text);
    //@@ 구분자

    fprintf(fp, "%s@@%s@@%s", plainText, signature, Alice_certFn);

    fclose(fp);

    return;

}

void set_combine2(char* finalfn, char* cfn, unsigned char* cipherText) {
    //from_Bob.txt에 밥에게 전송 보낼 메세지 쓰기


    FILE* read_fp = NULL;
    FILE* write_fp = NULL;

    if (0 != fopen_s(&read_fp, cfn, "rb")) { //cfn 파일을 바이너리 읽기모드로 열기
        printf("%s 파일을 열지 못하였습니다. ", cfn);

        return;

    }
    char buffer[1000] = "";

    fgets(buffer, 1000, read_fp); // read_fp를 1000 크기만큼 버퍼에 쓰기

    fopen_s(&write_fp, finalfn, "wb"); //finafn 파일을 바이너리 쓰기모드로 열기


    fprintf(write_fp, "%s@@%s", buffer, cipherText);// from_Bob.txt에 암호화된 메세지+디지털봉투 (@@구분자)

    fclose(read_fp);
    fclose(write_fp);


    return;

}

void getTimeSubstr(char buff[]) {
    struct _timeb objTimeb;
    // _timeb 구조체 
    // time_t time; // time_t 970년 1월 1일 자정(00:00:00)(UTC(협정 세계시)) 이후의 시간(초)
    // unsigned short; // 1/1000초
    // short timezone; //세계 표준시와 현지와의 분수 차이
    // short dstflag; //써머타임 적용시 0이 아닌 값, 그 밖에는 0

    struct tm t;
    // tm 구조체
    // int tm_sec; 현재 시각이 몇초인지 0~61 
    // int tm_min; 현재 시각이 몇분인지 0~59
    // int tm_hour; 현재 시각이 몇시인지 0~23
    // int tm_mday; 지금이 몇일인지 1~31
    // int tm_mon; 지금이 몇월인지 0~11
    // int tm_year; 지금이 몇년인지
    // int tm_wday; 지금이 무슨 요일인지 0~6
    // int tm_yday; 1월 1일부터 몇 일이 지났는지 0~365
    // int tm_isdst; 서머 타임제를 실시하고 있는지(1) 아닌지(0)

    _ftime_s(&objTimeb);
    // 현재 현지 시간을 가져와서 objTImeb 구조체 변수에 저장

    localtime_s(&t, &objTimeb.time);
    // 두번째 파라미터에 저장된 시간을 변환하여 첫번째 파라미터에 저장
    //초 단위 값으로 지역 시각을 구함

    //memcpy 메모리 일부분 복사
    //두번째 파라미터가 가리키는 곳부터 (세번째 파라미터 수)4 바이트 만큼을 첫번째 파라미터가 가리키는 곳에 복사 
    memcpy(buff, &(t.tm_sec), 4);
    memcpy(buff + 4, &(objTimeb.millitm), 4);

    return;
}

void create_randomKey(char seedbuff[], unsigned char mykey[], unsigned char iv[]) { //랜덤으로 키 생성
    getTimeSubstr(seedbuff);
    RAND_seed(seedbuff, 8);  //unsigned char *buf, int num
    //seedbuff의 8바이트를 PRNG상태로 혼합
    //PRNG상태는 현재시간 사용

    int n = RAND_bytes(mykey, 64); // mykey의 byte =64
    int m = RAND_bytes(iv, 16);// iv의 byte = 16
    // 암호화적으로 강력한 숫자의 의사난수 바이트를 첫번째 파라미터에 넣음
    // PRNG에 예측할 수없는 바이트 시퀀스를 보장하기에 충분한 임의성이 부여되지 않은 경우 오류가 발생
    // 성공하면 1, 그렇지 않으면 0 반환

    if (n == 1 && m == 1) {
        printf("대칭키: %s \n", mykey);
        printf("초기벡터: %s \n\n", iv);
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
    // pfn 파일을 바이너리 형식의 읽기 모드로 열어서 ptf에 할당
    fopen_s(&ctf, cfn, "wb");
    // cfn 파일을 바이너리 형식의 쓰기 모드로 열어서 ctf에 할당
    //EVP_CIPHER_CTX_init(ctx);
    // 암호 콘텍스 ctx를 초기화한다



    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, 1);
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, mykey, iv, AES_ENCRYPT);
    // 암호화를 위해 암호 컨텍스트 ctx를 설정 , ctx를 초기화, 암호화 형식 EVP_aes_128_cbc , impl은 NULL로 초기화,
    // 대칭키로 mykey, CBC모드의 초기 벡터 = iv, AES_ENCRYPT암호 flag 1일경우 암호화, 0일경우 복호화

    while ((in_len = fread(ptext, 1, MAXBUFF, ptf)) > 0) {
        //ptf에서 MAXBUFF개의 원소를 가지는 배열을 읽어온다. 각 원소의 크기는 1바이트이고 ptext가 가리키는 배열에 넣게된다.
        ret = EVP_CipherUpdate(ctx, ctext, &out_len, ptext, in_len);
        // 암호화 실행 , ctext = 암호된 데이터가 저장될 버퍼, out_len = 암호가 성공한 바이트의 크기, ptext = 암호화 평문, in_len = 암호화 평문 길이
        fwrite(ctext, 1, out_len, ctf);
        //ctext의 데이터를 ctf가 가리키는 파일에 적음, 1은 쓰고싶은 데이터의 단위크기(바이트), out_len는 데이터 저장 개수

        printf("AES암호화 전 데이터의 길이: %d \n", in_len);
    }


    fclose(ptf);
    ret = EVP_CipherFinal_ex(ctx, ctext, &out_len);
    // 암호화 결과 저장, ctext = 암호된 데이터가 저장될 버퍼, out_len = 암호된 데이터의 길이가 저장
    printf("AES암호화 후 데이터의 길이: %d \n", out_len);
    fwrite(ctext, 1, out_len, ctf);
    fclose(ctf);
    EVP_CIPHER_CTX_cleanup(ctx);

    return out_len;
}

void RSA_encryption(EVP_PKEY_CTX* ctx, unsigned char mykey[], EVP_PKEY* pubkey, size_t outlen, unsigned char* cipherText) {
    //암호화 - 대칭키(mykey)를 밥의 공개키(pubkey)로 암호화

    ctx = EVP_PKEY_CTX_new(pubkey, NULL);                           //ctx 생성 및 키 설정
    // 파라미터 타입은 EVP_PKEY_CTX, 공개키 알고리즘의 공개키 할당
    EVP_PKEY_encrypt_init(ctx);                                    //ctx 초기화
    // 파라미터 타입은 EVP_PKEY_CTX, 암호 작업에 키 pkey를 사용하여 공개 키 알고리즘 내용을 초기화
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING);                  //패딩 설정
    // ctx에 대한 RSA 패딩 모드를 설정,패딩모드는 RSA_NO_PADDING
    EVP_PKEY_encrypt(ctx, NULL, &outlen, mykey, MODULUS / 8);         //buffer 길이 결정
    // ctx를 사용하여 공개키 암호 작업 buffer길이 결정, 암호화할 데이터 plainText및 MODULUS / 8의 크기를 매개 변수를 사용하여 지정,
    //NULL인경우 출력 버퍼의 최대크기가 &outlen매게변수에 기록
    EVP_PKEY_encrypt(ctx, cipherText, &outlen, mykey, MODULUS / 8);      //RSA 암호화
    // ctx를 사용하여 공개키 암호화 작업 수행, 암호화할 데이터 plainText및 MODULUS / 8 크기를 매개 변수를 사용하여 지정,
    // 암호문(cipherText) 버퍼의 크기가 &outlen매게변수에 기록
    EVP_PKEY_CTX_free(ctx);

    printf("RSA 암호화 후 디지털 봉투의 길이: %d \n", outlen);

}

void RSA_decryption(char* pfn, unsigned char* encrypted, unsigned char* decrypted, int _public) //pfn 파일을 입력 받아 복호화
{   //encrypted == ciperText
   //decrypted == mykey

    EVP_PKEY* _pkey = NULL;
    FILE* pfp = NULL;

    if (!_public) //공용키면 이곳에서 공용키 설정으로 파일 열기
    {
        //공개키 저장
        fopen_s(&pfp, pfn, "wb");
        PEM_write_PKCS8PrivateKey(pfp, _pkey, NULL, NULL, 0, 0, NULL);
        fclose(pfp);

        //공개키 로드
        fopen_s(&pfp, pfn, "rb");
        PEM_read_PrivateKey(pfp, &_pkey, 0, NULL);
        fclose(pfp);
    }
    else //개인키면 이곳에서 개인키 설정으로 파일 열기
    {
        //개인키 저장
        fopen_s(&pfp, pfn, "wb");
        PEM_write_PUBKEY(pfp, _pkey);
        fclose(pfp);

        //개인키 로드
        fopen_s(&pfp, pfn, "rb");
        PEM_read_PUBKEY(pfp, &_pkey, 0, NULL);
        fclose(pfp);
    }

    size_t outlen = 0;
    int result = 0;
    EVP_PKEY_CTX* ctx = NULL;
    ctx = EVP_PKEY_CTX_new(_pkey, NULL);                           //ctx 생성 및 키 설정
    // 파라미터 타입은 EVP_PKEY, 공개키 알고리즘의 개인키 할당
    EVP_PKEY_decrypt_init(ctx);                                    //ctx 초기화
    // 파라미터 타입은 EVP_PKEY_CTX,  복호화 작업에 키 pkey를 사용하여 공개 키 알고리즘 내용를 초기화한다.
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING);                  //패딩 설정
    // ctx에 대한 RSA 패딩 모드를 설정,패딩모드는 RSA_NO_PADDING
    EVP_PKEY_decrypt(ctx, NULL, &outlen, encrypted, outlen);            //buffer 길이 결정
    // ctx를 사용하여 공개키 복호 작업 buffer길이 결정, 복호화할 데이터 encrypted및 outlen의 크기를 매개 변수를 사용하여 지정,
    // NULL인경우 출력 버퍼의 최대크기가 &outlen 매개변수에 기록
    result = EVP_PKEY_decrypt(ctx, decrypted, &outlen, encrypted, outlen);      //RSA 복호화
    //ctx를 사용하여 공개키 복호화 작업 수행, 복호화할 데이터 encrypted및 otlen의 크기를 매개 변수를 사용하여 지정,
    //원문(decrypted) 버퍼의 크기가 &outlen 매개변수에 기록

    EVP_PKEY_CTX_free(ctx);
}

void AES_decryption(char* cfn, char* dfn, unsigned char mykey[], unsigned char iv[]) {  //AES 복호화
    FILE* ctf, * dtf;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int in_len, out_len = 0, ret;
    unsigned char ctext[MAXBUFF + 8];
    unsigned char dtext[MAXBUFF + 16];

    fopen_s(&ctf, cfn, "rb");
    // cfn 파일을 바이너리 형식의 읽기 모드로 열어서 ctf 에 할당
    fopen_s(&dtf, dfn, "wb");
    // dfn 파일을 바이너리 형식의 쓰기 모드로 열어서 dtf에 할당

    // 암호 콘텍스 ctx를 초기화한다
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, 1);
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, mykey, iv, AES_DECRYPT);
    // 복호화를 위해 암호 컨텍스트 ctx를 설정 , ctx를 초기화, 복호화 형식 EVP_aes_128_cbc , impl은 NULL로 초기화,
    // 대칭키로 mykey, CBC모드의 초기 벡터 = iv, AES_ENCRYPT암호 flag 1일경우 복호화
    while ((in_len = fread(ctext, 1, MAXBUFF, ctf)) > 0) {
        // ctf에서 MAXBUFF개의 원소를 가지는 배열을 읽어온다. 각 원소의 크기는 1바이트이고 Ctext가 가리키는 배열에 넣게된다.
        ret = EVP_CipherUpdate(ctx, dtext, &out_len, ctext, in_len);
        // 복호화 실행 , dtext = 복호된 데이터가 저장될 버퍼, out_len = 복호가 성공한 바이트의 크기, dtext = 복호화된 평문, in_len = 복호화된 평문 길이
        fwrite(dtext, 1, out_len, dtf);
        //dtext의 데이터를 dtf가 가리키는 파일에 적음, 1은 쓰고데이터의 단위크기(바이트), out_len는 데이터 저장 개수
    }
    fclose(ctf);
    ret = EVP_CipherFinal_ex(ctx, dtext, &out_len);
    // 복호화 결과 저장, dtext = 복호된 데이터가 저장될 버퍼, out_len = 복호된 데이터의 길이가 저장
    fwrite(dtext, 1, out_len, dtf);

    fclose(dtf);
    EVP_CIPHER_CTX_cleanup(ctx);
}



//분리할 파일, 암호화된 메세지 크기, 디지털봉투 크기, 분리한 암호화된 메세지, 분리한 디지털 봉투
void set_Divide(char* finalfn, char* cfn, unsigned char* cipherText)
{
    FILE* read_fp = NULL;

    char buffer[1000] = "";

    fopen_s(&read_fp, finalfn, "rb"); //바이너리 읽기모드로 finalfn을 열어 read_fp 할당
    fgets(buffer, 1000, read_fp); //read_fp 파일 내용을 buffer에 저장


    char* ptr = strtok(buffer, "@@");

    ptr = strtok(NULL, "@");

    fclose(read_fp);

}

void set_Divide2(char* pfn, unsigned char* plainText, unsigned char* signature, char* Alice_certFn) //메시지, 인증서, 서명으로 나누기
{
    FILE* read_fp = NULL;

    char buffer[1000] = "";

    fopen_s(&read_fp, pfn, "rb"); //바이너리 읽기모드로 pfn을 열어 read_fp 할당
    fgets(buffer, 1000, read_fp); //read_fp 파일 내용을 buffer에 저장

    //구분자(@@)로 분리하기 
    char* ptr = strtok(buffer, "@@");
    plainText = (unsigned char*)ptr;

    ptr = strtok(NULL, "@");
    signature = (unsigned char*)ptr;

    ptr = strtok(NULL, "@");
    Alice_certFn = (char*)ptr;


    printf("분리한 plaintext: %s \n", plainText);
    printf("분리한 signature: %s \n", signature);
    printf("분리한 앨리스의 공개키 인증서: %s \n\n", Alice_certFn);

    return;
}

// pubkey : 상대방의 공개키
// signature : 디지털 서명
// plainText : 복호화된 메시지
// 리턴 값이 1일 시 서명 인증 통과, 그 외 실패
int signature_decrypt(EVP_PKEY* pubkey, unsigned char* signature, unsigned char* plainText, size_t outlen) // 서명용 복호화
{
    //검증용 복호화 - 공개키로 복호화 및 해시 알고리즘 지정
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubkey, NULL);                                 //ctx 생성 및 키 설정
    // 파라미터 타입은 EVP_PKEY, 공개키 알고리즘의 공개키 할당
    EVP_PKEY_verify_init(ctx);                                          //ctx 초기화
    // 파라미터 타입은 EVP_PKEY_CTX, 서명 복호화 작업에 키 pkey를 사용하여 공개 키 알고리즘 내용를 초기화한다.
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);                     //패딩 설정
    // ctx에 대한 RSA 패딩 모드를 설정,패딩모드는 RSA_PKCS1_PADDING이며 flen은 PKCS #1 v1.5기반 패딩모드의 경우 RSA_size ( rsa )-11미만
    EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());                        //해시 알고리즘 설정
    // 서명복호화에 사용되는 해시알고리즘을 설정, sha256()해시 알고리즘 사용
    int result = EVP_PKEY_verify(ctx, signature, outlen, plainText, EVP_MD_size(EVP_sha256()));//RSA 복호화
    // 결과는 ctx를 사용하여 공개키 서명복호화 작업 수행, 서명할 데이터 plainText및 sha256의 해시크기를 매겨 변수를 사용하여 지정,
    // 서명 버퍼의 크기가 outlen 매개변수에 기록

    EVP_PKEY_CTX_free(ctx);

    return result;


}

// ************************************** main ***********************************************
int main() {

    EVP_PKEY_CTX* ctx = NULL;  // 공개키 알고리즘이 담겨있는 구조체

    unsigned char* plainText = (unsigned char*)"Hello RSA"; //평문

    printf("plainText: %s \n\n", plainText);

    printf("--------------------------------------------------------\n\n");

    // ********************** 키 쌍 생성시 사용하는 변수 **********************
    //privkey(개인키), pubkey(공개키)
    size_t outlen_signatureE = 0, result = 0;
    //앨리스
    EVP_PKEY* Alice_pkey = NULL, * Alice_privkey = NULL, * Alice_pubkey = NULL;
    FILE* Alice_privfp = NULL, * Alice_pubfp = NULL;
    char* Alice_privfn = (char*)"Alice_privateKey.pem";
    char* Alice_pubfn = (char*)"Alice_publicKey.pem";
    //밥 
    EVP_PKEY* Bob_pkey = NULL, * Bob_privkey = NULL, * Bob_pubkey = NULL;
    FILE* Bob_privfp = NULL, * Bob_pubfp = NULL;
    char* Bob_privfn = (char*)"Bob_privateKey.pem";
    char* Bob_pubfn = (char*)"Bob_publicKey.pem";


    // ********************** 디지털 서명시 사용하는 변수 **********************
    unsigned char* signature; //서명한 값 저장
    signature = (unsigned char*)calloc(1, MODULUS + EVP_MAX_BLOCK_LENGTH);   //출력이 Modulus 보다 클 수도 있다
    //1 크기의 변수를  MODULUS + EVP_MAX_BLOCK_LENGTH개 만큼 저장할 수 있는 메모리 공간 할당


    // ********************** 인증서 생성시 사용하는 변수 **********************
    // 앨리스 
    X509* Alice_x509 = NULL; // 인증서 
    char* Alice_certFn = (char*)"Alice_Cert.der"; //인증서 파일
    //밥
    X509* Bob_x509 = NULL;//인증서
    char* Bob_certFn = (char*)"Bob_Cert.der"; //인증서 파일


    // ********************** AES 암호화시 사용하는 변수 **********************
    char seedbuff[MAXBUFF] = ""; // seedbuff = 1024(MAXBUFF)
    unsigned char mykey[EVP_MAX_KEY_LENGTH] = "\0"; // mykey = 64바이트(EVP_MAX_KEY_LENGTH) 대칭키(세션키)
    unsigned char iv[EVP_MAX_IV_LENGTH] = "\0"; // iv = 16바이트(EVP_MAX_IV_LENGTH) 최대블럭크기
    char* pfn = (char*)"before_aesE.txt"; //암호화 전 메세지가 담긴 파일 이름
    char* cfn = (char*)"after_aesE.txt"; // 암호화 후 메세지가 담긴 파일 이름
    int outlen_aesE = 0; //aes 암호화 후 데이터의 크기





    // ********************** RSA 암호화시 사용하는 변수 **********************
    EVP_PKEY* Bob_pubkey_x509; //인증서에서 추출한 밥의 공개키
    size_t outlen_rsaE = 0; //암호문(cipherText) 버퍼의 크기가 outlen매게변수에 기록
    unsigned char* cipherText; //디지털봉투
    cipherText = (unsigned char*)calloc(1, MODULUS + EVP_MAX_BLOCK_LENGTH);
    int rsa_out_len = 0; //rsa 암호화 후 데이터의 크기 = 디지털봉투의 크기


    // ********************** 앨리스 ----> 밥 전송 파일 **********************
    char* finalfn = (char*)"from_Bob.txt";


    // ********************** RSA 복호화시 사용하는 변수 **********************
    unsigned char* cipherText2; //디지털봉투
    cipherText2 = (unsigned char*)calloc(1, MODULUS + EVP_MAX_BLOCK_LENGTH);


    //모든 알고리즘 사용
    OpenSSL_add_all_algorithms();
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);




    // ********************** 앨리스 키 생성 **********************
    printf("E1. 앨리스 키를 생성합니다. \n\n");
    printf("앨리스 비밀키 파일 이름: %s \n", Alice_privfn);
    printf("앨리스 공개키 파일 이름: %s \n\n", Alice_pubfn);

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);      //ctx 생성
    //첫번째 파라미터 타입은 EVP_PKEY, RSA 공개키 알고리즘 할당
    EVP_PKEY_keygen_init(ctx);                     //ctx 초기화
    // 파리미터 타입은 EVP_PKEY_CTX, 키 생성 조작에 키 pkey를 사용하여 공개키 알고리즘 내용을 초기화
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, MODULUS);      //키 길이 설정
    // 키 길이 =512
    EVP_PKEY_keygen(ctx, &Alice_pkey);                  //키 생성
    // 키 생성 작업을 수행하는 함수이며 생성된 키는 pkey에 기록
    EVP_PKEY_CTX_free(ctx);                        //ctx 반환


    private_key_save(Alice_privfp, Alice_privfn, Alice_pkey); //개인키 저장
    public_key_save(Alice_pubfp, Alice_pubfn, Alice_pkey); //공개 키 저장

    //개인 키 로드 => 함수 인식 못함

    fopen_s(&Alice_privfp, Alice_privfn, "rb");
    // prvifn 파일을 바이너리 형식의 읽기 모드로 열어서 pevfp에 할당
    PEM_read_PrivateKey(Alice_privfp, &Alice_privkey, 0, NULL);
    fclose(Alice_privfp);

    //공개키 로드 => 함수 인식 못함

    fopen_s(&Alice_pubfp, Alice_pubfn, "rb");
    // pubfn 파일을 바이너리 형식의 읽기 모드로 열어서 pubfp에 할당
    PEM_read_PUBKEY(Alice_pubfp, &Alice_pubkey, 0, NULL);
    fclose(Alice_pubfp);

    if (Alice_privkey != NULL && Alice_pubkey != NULL) {

        printf("앨리스 키(개인키, 공개키) 생성 완료 \n\n");
    }



    printf("--------------------------------------------------------\n\n");



    // ********************** 밥 키 생성 **********************
    printf("E2. 밥 키를 생성합니다. \n\n");

    printf("밥 비밀키 파일 이름: %s \n", Bob_privfn);
    printf("밥 공개키 파일 이름: %s \n\n", Bob_pubfn);

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);      //ctx 생성
    //첫번째 파라미터 타입은 EVP_PKEY, RSA 공개키 알고리즘 할당
    EVP_PKEY_keygen_init(ctx);                     //ctx 초기화
    // 파리미터 타입은 EVP_PKEY_CTX, 키 생성 조작에 키 pkey를 사용하여 공개키 알고리즘 내용을 초기화
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, MODULUS);      //키 길이 설정
    // 키 길이 =512
    EVP_PKEY_keygen(ctx, &Bob_pkey);                  //키 생성
    // 키 생성 작업을 수행하는 함수이며 생성된 키는 pkey에 기록
    EVP_PKEY_CTX_free(ctx);                        //ctx 반환


    private_key_save(Bob_privfp, Bob_privfn, Bob_pkey); //개인키 저장
    public_key_save(Bob_pubfp, Bob_pubfn, Bob_pkey); //공개 키 저장

    //개인 키 로드 => 함수 인식 못함

    fopen_s(&Bob_privfp, Bob_privfn, "rb");
    // prvifn 파일을 바이너리 형식의 읽기 모드로 열어서 privfp에 할당
    PEM_read_PrivateKey(Bob_privfp, &Bob_privkey, 0, NULL);
    fclose(Bob_privfp);

    //공개키 로드 => 함수 인식 못함

    fopen_s(&Bob_pubfp, Bob_pubfn, "rb");
    // pubfn 파일을 바이너리 형식의 읽기 모드로 열어서 pubfp에 할당
    PEM_read_PUBKEY(Bob_pubfp, &Bob_pubkey, 0, NULL);
    fclose(Bob_pubfp);

    if (Bob_privkey != NULL && Bob_pubkey != NULL) {

        printf("밥 키(개인키, 공개키) 생성 완료 \n\n");
    }

    printf("--------------------------------------------------------\n\n");

    // ********************** 서명용 암호화 ********************** 
    printf("E3. 서명 암호화를 진행합니다. \n\n");
    printf("해시 함수: SHA-256 \n");
    signature_encrypt(ctx, Alice_privkey, signature, plainText, outlen_signatureE);
    printf("signature: %s \n\n", signature);

    printf("--------------------------------------------------------\n\n");

    // ********************** 앨리스 인증서 생성 **********************
    printf("E4. 앨리스 인증서를 생성합니다. \n\n");
    printf("앨리스 인증서 파일 이름: %s \n\n", Alice_certFn);

    create_cert(1, Alice_x509, Alice_pubkey, Alice_privkey, Alice_certFn);
    EVP_PKEY_free(Alice_pkey);

    if (x509_check(Alice_certFn, Alice_x509)) {
        //Alice_x509의 서명을 Alice_pubkey로 확인, 1이 나오면 정상작동
        printf("앨리스 인증서 생성 완료 \n\n");
    }
    printf("--------------------------------------------------------\n\n");

    // ********************** 밥 인증서 생성 **********************
    printf("E5. 밥 인증서를 생성합니다. \n\n");

    printf("밥 인증서 파일 이름: %s \n\n", Bob_certFn);

    create_cert(2, Bob_x509, Bob_pubkey, Bob_privkey, Bob_certFn);
    EVP_PKEY_free(Bob_pkey);


    if (x509_check(Bob_certFn, Bob_x509)) {
        //Bob_x509의 서명을 Bob_pubkey로 확인, 1이 나오면 정상작동
        printf("밥 인증서 생성 완료 \n\n");
    }
    printf("--------------------------------------------------------\n\n");


    // ********************** 메세지 + 디지털서명 + 앨리스공개키인증서 합치기**********************
    printf("E6. 메세지 + 디지털서명 + 앨리스공개키인증서 파일을 생성합니다. \n\n");
    printf("파일 이름: %s \n", pfn);
    set_combine(pfn, plainText, signature, Alice_certFn);
    //before_aesE.txt에 암호화할 메세지 쓰기
    printf("파일 내용: "); file_read(pfn);
    printf("--------------------------------------------------------\n\n");

    // ********************** 대칭키와 IV 생성 **********************
    printf("E7. 대칭키와 초기벡터(IV)를 생성합니다. \n\n");
    create_randomKey(seedbuff, mykey, iv); //의사난수 생성기로 키 생성 => 대칭키
    printf("--------------------------------------------------------\n\n");

    // ********************** AES 암호화 **********************
    printf("E8. AES 암호화를 진행합니다. \n\n");
    printf("AES 암호화 알고리즘: AES-128-CBC \n");
    outlen_aesE = AES_encryption(pfn, cfn, mykey, iv); //AES 대칭키 암호화

    printf("파일 이름: %s \n", cfn);
    printf("암호화한 파일 내용: "); file_read(cfn);
    printf("--------------------------------------------------------\n\n");



    // ********************** 밥 인증서에서 공개키 추출 **********************
    printf("E9. 밥 인증서에서 공개키를 추출합니다. \n\n");

    X509* root_x509 = NULL;
    FILE* fp = NULL;

    printf("밥의 인증서 파일 이름: %s \n", Alice_certFn);
    Bob_pubkey_x509 = x509_pop(Bob_certFn, root_x509);


    printf("--------------------------------------------------------\n\n");

    // ********************** RSA 암호화 **********************
    printf("E10. RSA 암호화를 진행합니다. \n\n");
    RSA_encryption(ctx, mykey, Bob_pubkey_x509, outlen_rsaE, cipherText);
    printf("cipherText : %s \n\n", cipherText);

    printf("--------------------------------------------------------\n\n");

    // ********************** 암호화된 메세지 + 디지털봉투 합치기**********************
    printf("E11. 암호화된 메세지 + 디지털봉투 파일을 생성합니다. \n\n");
    set_combine2(finalfn, cfn, cipherText);
    printf("파일 이름: %s \n", finalfn);
    printf("파일 내용: "); file_read(finalfn); //finalfn의 내용 출력

    printf("--------------------------------------------------------\n\n");
    printf("--------------------------------------------------------\n\n");
    printf("--------------------------------------------------------\n\n");

    // ********************** 암호화된 메세지, 디지털봉투 분리하기**********************
    printf("D1. 파일을 암호화된 메세지, 디지털봉투 파일로 분리합니다. \n\n");
    char* cfn2 = (char*)"before_aesD"; //분리한 암호화된 메세지 저장

    set_Divide(finalfn, cfn2, cipherText2);
    //분리할 파일, 분리한 암호화된 메세지, 분리한 디지털 봉투

    printf("cipherText: %s \n", cipherText);
    printf("암호화된 메세지: "); file_read(cfn);

    printf("--------------------------------------------------------\n\n");





    // ********************** RSA 복호화 **********************
    printf("D2. RSA 복호화를 진행합니다. \n\n");
    //RSA_decryption(char* pfn, unsigned char* encrypted, unsigned char* decrypted, int _public)
    printf("복호화 하기 전 cipherText: %s \n", cipherText);
    RSA_decryption(Bob_privfn, cipherText, mykey, 1); //Bob의 개인키로 디지털 봉투를 열어 mykey에 대칭키 저장
    printf("복호화로 얻은 대칭 키: %s \n\n", mykey);
    printf("--------------------------------------------------------\n\n");


    // ********************** AES 복호화 **********************

    char* dfn = (char*)"after_aesD.txt"; //복호화 후 메세지가 담긴 파일

    printf("D3. AES 복호화를 진행합니다. \n\n");
    printf("복호화하기 전 메세지: "); file_read(cfn);
    //AES_decryption(char* cfn, char* dfn, unsigned char mykey[], unsigned char iv[])
    AES_decryption(cfn, dfn, mykey, iv);

    printf("AES 복호화 알고리즘: AES-128-CBC \n");
    printf("복호화로 얻는 파일 이름: %s \n", dfn);
    printf("복호화로 얻은 파일 내용: ");  file_read(dfn);

    printf("--------------------------------------------------------\n\n");


    // ********************** 메세지, 디지털서명, 앨리스공개키인증서 분리하기**********************
    printf("D4. 파일을 메세지, 디지털서명, 앨리스공개키인증서로 분리합니다. \n\n");

    unsigned char* plainText2 = NULL; //분리하여 메세지 저장
    unsigned char* signature2; //분리하여 서명한 값 저장
    signature2 = (unsigned char*)calloc(1, MODULUS + EVP_MAX_BLOCK_LENGTH);   //출력이 Modulus 보다 클 수도 있다
    //1 크기의 변수를  MODULUS + EVP_MAX_BLOCK_LENGTH개 만큼 저장할 수 있는 메모리 공간 할당
    char* Alice_certFn2 = NULL; //분리하여 앨리스공개키인증서 저장

    printf("분리할 파일 이름: %s \n", dfn);

    set_Divide2(dfn, plainText2, signature2, Alice_certFn2);

    printf("--------------------------------------------------------\n\n");

    // ********************** 앨리스 인증서에서 공개키 추출 **********************
    printf("D5. 앨리스 인증서에서 공개키를 추출합니다. \n\n");

    root_x509 = NULL;
    EVP_PKEY* Alice_pubkey_x509; //인증서에서 추출한 앨리스의 공개키

    printf("앨리스의 인증서 파일 이름: %s \n", Alice_certFn);
    Alice_pubkey_x509 = x509_pop(Alice_certFn, root_x509);


    printf("--------------------------------------------------------\n\n");

    // ********************** 서명용 복호화 **********************
    printf("D6. 서명용 복호화 후 메세지 다이제스트를 비교합니다. \n\n");
    printf("해시함수: SHA-256 \n\n");
    int result_S = signature_decrypt(Alice_pubkey_x509, signature, plainText, outlen_signatureE);
    printf("plain text: %s\n", plainText);
    printf("signature: %s\n", signature);
    printf("result: %d\n", result_S);

    printf("--------------------------------------------------------\n\n");


    getchar();
    return 0;
}