# SPDX-License-Identifier: GPL-2.0-only

obj-$(CONFIG_CRC32)	+= crc32.o
obj-pbl-$(CONFIG_CRC_ITU_T)	+= crc-itu-t.o
obj-$(CONFIG_CRC7)	+= crc7.o
obj-$(CONFIG_DIGEST)	+= digest.o
obj-$(CONFIG_DIGEST_CRC32_GENERIC)	+= crc32_digest.o
obj-$(CONFIG_DIGEST_HMAC_GENERIC)	+= hmac.o
obj-$(CONFIG_DIGEST_MD5_GENERIC)	+= md5.o
obj-$(CONFIG_DIGEST_SHA1_GENERIC)	+= sha1.o
obj-$(CONFIG_DIGEST_SHA224_GENERIC)	+= sha2.o
obj-$(CONFIG_DIGEST_SHA256_GENERIC)	+= sha2.o
pbl-$(CONFIG_PBL_VERIFY_PIGGY)		+= sha2.o
pbl-$(CONFIG_PBL_VERIFY_PIGGY)		+= digest.o
obj-$(CONFIG_DIGEST_SHA384_GENERIC)	+= sha4.o
obj-$(CONFIG_DIGEST_SHA512_GENERIC)	+= sha4.o
obj-y	+= memneq.o

obj-$(CONFIG_CRYPTO_PBKDF2)	+= pbkdf2.o
obj-$(CONFIG_CRYPTO_RSA)	+= rsa.o
obj-$(CONFIG_CRYPTO_KEYSTORE)	+= keystore.o

extra-$(CONFIG_CRYPTO_RSA_BUILTIN_KEYS) += rsa-keys.h

ifdef CONFIG_CRYPTO_RSA_BUILTIN_KEYS

$(obj)/rsa.o: $(obj)/rsa-keys.h
$(eval $(call config_filename,CRYPTO_RSA_KEY))
$(obj)/rsa-keys.h: FORCE
	$(call cmd,rsa_keys,$(CONFIG_CRYPTO_RSA_KEY_NAME_HINT):$(CRYPTO_RSA_KEY_SRCPREFIX)$(CRYPTO_RSA_KEY_FILENAME))
endif
