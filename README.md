# SNI Tool

> ![NOTE] В процессе разработки

Инструмент для поиска "правильного" SNI (wSNI).

## Использование

Прежде всего вам понадобится актуальный `asn.csv`. Положите его рядом
с `snitool`. Также вы можете попытаться собрать `asn.csv` самостоятельно:

    ```sh
    snitool db build
    ```

После этого вы сможете искать ASN, CIDR и wSNI по целевому ip или хосту:

    ```sh
    snitool lookup asn <ip or host>
    snitool loopup wsni <ip or host>
    ```

Например:

* Найти ASN для example.com:

    ```sh
    > snitool lookup asn example.com
    IP              | CIDR               | ASN        | ASN Name
    8.6.112.6       | 8.6.112.0/24       | 13335      | CLOUDFLARENET, US
    8.47.69.6       | 8.47.69.0/24       | 13335      | CLOUDFLARENET, US
    ```

* Найти wSNI для example.com:

    ```sh
    > snitool lookup wsni example.com
    IP              | CIDR               | ASN        | ASN Name
    8.6.112.6       | 8.6.112.0/24       | 13335      | CLOUDFLARENET, US
    8.47.69.6       | 8.47.69.0/24       | 13335      | CLOUDFLARENET, US

    Collecting whitelisted SNIs...
    ASN 13335:
    ***.com.
    ...
    ...
    ```
