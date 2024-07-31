#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* On definit les operations binaires dans le preprocesseur, pour les réutiliser indépendamment des scopes*/
#define ROTR(x, n) ((x >> n) | (x << (32 - n)))
#define SHR(x, n) (x >> n)

#define CH(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))
/* On definit nos constantes de hash*/
static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
/*Ce sont les premiers mots d'initialisation, sur lesquelles vont s'appuyer les blocs du message*/
static const uint32_t h0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};
/*La fonction de padding, pour arranger notre message de manière à obtenir des blocs de 64 mots de 32 bits*/
void sha256_pad(uint8_t *message, uint64_t Taille_Message) {
    uint64_t Taille_Padde = Taille_Message+ 1 + 8;// Le 1 pour la place du 1 hexadécimal : 0x80 et le 8 pour allouer la place des 64 bits de la taille du message
    while (Taille_Padde % 64 != 0) {
        Taille_Padde++;
    }

    message[Taille_Message] = 0x80;
    for (uint64_t i =Taille_Message + 1; i < Taille_Padde - 8; i++) {
        message[i] = 0x00;
    }

    uint64_t Taille_Binaire= Taille_Message * 8;
    for (uint64_t i = 0; i < 8; i++) {
        message[Taille_Padde - 1 - i] = (Taille_Binaire>> (i * 8)) & 0xff;
}
}
/* On forme nos blocs, les 16 premiers etant dejà formes, on les ajoute par operations binaires, et les 48 autres mod64 sont formes par les operations SIG0 et SIG1*/
void sha256_formattage(const uint8_t *block, uint32_t *m) {
    for (int i = 0; i < 16; i++) {
        m[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) |
               (block[i * 4 + 2] << 8) | (block[i * 4 + 3]);
    }

    for (int i = 16; i < 64; i++) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }
}
/*La fonction de compression, pour "melanger et hacher" notre message avec nos constantes*/
void sha256_compress(uint32_t *hash, const uint32_t *m) {
    uint32_t a, b, c, d, e, f, g, h;
    a = hash[0];
    b = hash[1];
    c = hash[2];
    d = hash[3];
    e = hash[4];
    f = hash[5];
    g = hash[6];
    h = hash[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        uint32_t t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;
}
// Le récapitulatif, en allouant statiquement la mémoire dont aura besoin
void sha256(const uint8_t *message, uint64_t Taille_Message, uint8_t *Resultat) {
    uint64_t Taille_Padde = Taille_Message + 1 + 8;
    while (Taille_Padde % 64 != 0) {
        Taille_Padde++;
    }

    uint8_t *Message_Padde = (uint8_t *)malloc(Taille_Padde);
    if (!Message_Padde) {
        fprintf(stderr, "Erreur Memoire\n");
        exit(1);
    }

    memcpy(Message_Padde, message, Taille_Message);
    sha256_pad(Message_Padde, Taille_Message);

    uint32_t hash[8];
    memcpy(hash, h0, sizeof(h0));

    for (uint64_t i = 0; i < Taille_Padde / 64; i++) {
        uint32_t m[64];
        sha256_formattage(Message_Padde + i * 64, m);
        sha256_compress(hash, m);
    }

    for (int i = 0; i < 8; i++) {
        Resultat[i * 4] = (hash[i] >> 24) & 0xff;
        Resultat[i * 4 + 1] = (hash[i] >> 16) & 0xff;
        Resultat[i * 4 + 2] = (hash[i] >> 8) & 0xff;
        Resultat[i * 4 + 3] = hash[i] & 0xff;
    }

    free(Message_Padde);
}
//Test
int main() {
    char message[256];
    uint8_t Resultat[32];
    char Choix;

    do {
        printf("Rentrez votre message : ");
        fgets(message, sizeof(message), stdin);

        size_t Taille_Message = strlen(message);
        if (message[Taille_Message - 1] == '\n') {
            message[Taille_Message - 1] = '\0';
        }

        sha256((const uint8_t *)message, strlen(message), Resultat);

        printf("SHA-256 Resultat:\n");
        for (int i = 0; i < 32; i++) {
            printf("%02x", Resultat[i]);
        }
        printf("\n");

        printf("Voulez-vous continuer ? (y/n): ");
        Choix = getchar();
        getchar();
    } while (Choix == 'y' || Choix == 'Y');

    return 0;
}

