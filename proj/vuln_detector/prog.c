#include <stdio.h>

void vuln(char* fmt) {
    printf(fmt);
}

void scanf_overflow(char* fmt) {
    char buff[128];
    scanf("%s", buff);
    
    sprintf(buff, fmt);
}

void gets_overflow() {
    char buff[10];
    gets(buff);
}

int main(){
    char buff[128];
    char c;
    puts("Insert into buffer");
    fgets(buff, 128, stdin);

    scanf("%c", &c);
    if( c == 'A'){
        vuln(buff);
        return 0;
    } else if ( c == 'B' ){
        scanf_overflow(buff);
        return 0;
    } else if ( c == 'o') {
        gets_overflow();
        return 0;
    } else {
        return 1;
    }
}