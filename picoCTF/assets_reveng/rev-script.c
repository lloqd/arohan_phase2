#include <stdio.h>
void main(){
    char buffer[32];
    char* password[] = "jU5t_a_sna_3lpm18g947_u_4_m9r54f";
    int i = 0;

    for (i=0; i<8; i++) {
            buffer[i] = password;
    }

    for (; i<16; i++) {
        buffer[i] = password[23-i];
    }

    for (; i<32; i+=2){
        buffer[i] = password[46-i];
    }

    for (i=31; i>=17; i-=2){
        buffer[i] = password[i];
    }
    printf("%s", buffer);
}