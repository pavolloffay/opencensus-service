#ifndef __LIBRARY_H__
#define __LIBRARY_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  const char* key;
  const char* value;
} attribute;

typedef struct {
  char *rule_id;
  char *rule_message;
  char *match_message;
  int paranoia_level;
} rule_match;

typedef struct {
  int count;
  rule_match* match_arr;
} rule_match_wrapper;

void modsecurity_init();

void *modsecurity_new_rule_engine(const char *config_dir, const char *file_name);

void *modsecurity_new_rule_engine_by_rules(const char *rules);

rule_match_wrapper *modsecurity_process_attributes(void *ptr, attribute *attr_arr, int count);

void modsecurity_cleanup_rule_match_wrapper(void *ptr);

void modsecurity_cleanup_rule_engine(void *ptr);

#ifdef __cplusplus
}
#endif

#endif