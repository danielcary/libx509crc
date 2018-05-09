#pragma once

#include <stdbool.h>

/**
 * Performs an HTTP GET request using the specified URL. Returns
 * content of the HTTP response. The returned content should be freed.
 * 
 * @param url the URL to perform the HTTP get on
 * @param content a pointer to where the HTTP content buffer will be located
 * @param len a pointer to the length of the HTTP content
 * 
 * @returns 0 on error, 1 on success
 */
int http_get_by_url(const char *url, void **content, int *len);

/**
 * Performs an HTTP GET request using the specified URL. Returns
 * content of the HTTP response. The returned content should be freed.
 * 
 * @param host the host name to connect to
 * @param port the port of the host to connect to
 * @param use_ssl true if it should be an HTTPS request
 * @param path the path part of the HTTP request
 * @param content a pointer to where the HTTP content buffer will be located
 * @param len a pointer to the length of the HTTP content
 * 
 * @returns 0 on error, 1 on success
 */
int http_get(const char *host, const char *port, bool use_ssl, const char *path, void **content, int *len);

/**
 * Parses a URL. Only works for URLS in this format: [schema://]host[:port][/path].
 * Any passed back values should be freed.
 * 
 * @param url the URL to parse
 * @param schema the schema of the URL
 * @param host the host of the URL
 * @param port the port number as a string. Automatically set to 80 if schema is
 *      HTTP or 443 if HTTPS.
 * @param path the path of the URL
 * 
 * @returns 1 on success, 0 on failure
 */
int http_parse_url(const char *url, char** schema, char **host, char **port, char **path);
