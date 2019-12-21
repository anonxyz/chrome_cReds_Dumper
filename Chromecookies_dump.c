#include<stdio.h>
#include<ctype.h>
#include<stdlib.h>
#include<sqlite3.h>
#include<windows.h>
#include<wincrypt.h>

int main()
{
    int rc;
    sqlite3 *db;
    rc=sqlite3_open("Cookies",&db);
    if(rc)
    {
        printf("Error opening database");
        return 1;
    }
    const char *sql="SELECT HOST_KEY,path,encrypted_value from cookies";
    sqlite3_stmt *pstmt;
    rc=sqlite3_prepare(db,sql,-1,&pstmt,0);
    if(rc!=SQLITE_OK)
    {
        printf("Prepare error");
        return 1;
    }
    rc=sqlite3_step(pstmt);
    while(rc==SQLITE_ROW)
    {
        printf("%s\t%s\t",sqlite3_column_text(pstmt,0),sqlite3_column_text(pstmt,1));
        DATA_BLOB enc_data,dec_data;
        enc_data.cbData=(DWORD)sqlite3_column_bytes(pstmt,2);
        enc_data.pbData=(byte*)malloc((int)enc_data.cbData);

        memcpy(enc_data.pbData,sqlite3_column_blob(pstmt,2),(int)enc_data.cbData);

        CryptUnprotectData(&enc_data,NULL,NULL,NULL,NULL,0,&dec_data);
        char *c=(char*)dec_data.pbData;
        while(isprint(*c))
        {
            printf("%c",*c);
            c++;
        }
        printf("\n");

        rc=sqlite3_step(pstmt);
    }

}
