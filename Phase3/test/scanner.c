#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <mysql/mysql.h>

#define HASH_LEN 33

// Función para calcular el hash MD5 de un archivo
int calcular_md5(const char *filename, char *hash_str) {
    unsigned char c[MD5_DIGEST_LENGTH];
    int i;
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("No se pudo abrir el archivo");
        return -1;
    }

    MD5_CTX mdContext;
    int bytes;
    unsigned char data[1024];

    MD5_Init(&mdContext);
    while ((bytes = fread(data, 1, 1024, file)) != 0)
        MD5_Update(&mdContext, data, bytes);
    MD5_Final(c, &mdContext);

    fclose(file);

    for (i = 0; i < MD5_DIGEST_LENGTH; i++)
        sprintf(&hash_str[i * 2], "%02x", c[i]);

    hash_str[32] = '\0';
    return 0;
}

// Función para consultar la base de datos
int buscar_hash_bd(const char *hash) {
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;

    const char *host = "localhost";
    const char *user = "usac";            // Cambia si tienes un usuario distinto
    const char *pass = "seguridad123";                // Cambia si tu root tiene contraseña
    const char *db   = "signatures";

    conn = mysql_init(NULL);
    if (conn == NULL) {
        fprintf(stderr, "mysql_init() falló\n");
        return -1;
    }

    if (mysql_real_connect(conn, host, user, pass, db, 0, NULL, 0) == NULL) {
        fprintf(stderr, "mysql_real_connect() falló: %s\n", mysql_error(conn));
        mysql_close(conn);
        return -1;
    }

    char query[256];
    snprintf(query, sizeof(query), "SELECT severidad FROM firmas WHERE hash = '%s'", hash);

    if (mysql_query(conn, query)) {
        fprintf(stderr, "Fallo en la consulta: %s\n", mysql_error(conn));
        mysql_close(conn);
        return -1;
    }

    res = mysql_store_result(conn);
    if (res == NULL) {
        mysql_close(conn);
        return -1;
    }

    int resultado = 0; // limpio por defecto
    if ((row = mysql_fetch_row(res))) {
        if (strcmp(row[0], "alta") == 0)
            resultado = 2; // malicioso
        else if (strcmp(row[0], "media") == 1)
            resultado = 1; // sospechoso
        else
            resultado = 0;
    }

    mysql_free_result(res);
    mysql_close(conn);
    return resultado;
}

int main() {
    char ruta[256];
    char hash[HASH_LEN];

    while (1) {
        printf("\nIngrese la ruta del archivo (0 para salir): ");
        fgets(ruta, sizeof(ruta), stdin);

        size_t len = strlen(ruta);
        if (len > 0 && ruta[len - 1] == '\n')
            ruta[len - 1] = '\0';

        if (strcmp(ruta, "0") == 0) {
            printf("Saliendo...\n");
            break;
        }

        if (calcular_md5(ruta, hash) == 0) {
            printf("🔍 Hash MD5 calculado: %s\n", hash);
            int res = buscar_hash_bd(hash);
            if (res == 0)
                printf("✅ Archivo limpio\n");
            else if (res == 1)
                printf("⚠️ Archivo sospechoso\n");
            else if (res == 2)
                printf("❌ Archivo malicioso\n");
            else
                printf("❗ Error al consultar la base de datos\n");
        } else {
            printf("❌ Error al calcular el hash del archivo\n");
        }
    }

    return 0;
}
