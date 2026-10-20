/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef GODA_PKG_DIAGNOSTICS_H
#define GODA_PKG_DIAGNOSTICS_H
#include <string.h>
/* Goda application codes, not Sony/system error codes. Preserve the reader's
 * exact reason separately; a failed check does not prove package corruption. */
struct fl_pkg_diagnostic {const char *code,*message;};
static inline struct fl_pkg_diagnostic fl_pkg_diagnose(const char *s){
#define DIAG(code,text) return (struct fl_pkg_diagnostic){"GODA-PKG-" code,text}
 if(strstr(s,"cancelled"))DIAG("CANCELLED","Çıkarma durduruldu. Yarım klasör tamamlanmış oyun olarak gösterilmez.");
 if(strstr(s,"zero-passcode"))DIAG("KEY","Bu paketin anahtar kontrolü geçmedi. Şu an yalnız sıfır parolalı PS4 fPKG destekleniyor.");
 if(strstr(s,"Invalid or unreadable package")||strstr(s,"PFS range"))DIAG("FORMAT","Paket başlığı veya boyutları okunamadı. Dosya eksik, geçersiz ya da desteklenmeyen türde olabilir.");
 if(strstr(s,"free space"))DIAG("SPACE","Hedefte yeterli boş alan doğrulanamadı. Oyun boyutuna ek olarak 64 MiB boş alan gerekir.");
 if(strstr(s,"already exists"))DIAG("EXISTS","Hedefte aynı adla bir dosya veya klasör var ya da oluşturulamıyor. Başka bir çıkarma konumu seç; mevcut içeriğin üzerine yazılmadı.");
 if(strstr(s,"SHA256")||strstr(s,"metadata disagree")||strstr(s,"Source package changed")||strstr(s,"Output size changed"))DIAG("VERIFY","Dosya doğrulaması başarısız. Çıktı tamamlanmış oyun olarak onaylanmadı; kaynak paket ve disk bağlantısını kontrol et.");
 if(strstr(s,"path")||strstr(s,"collision")||strstr(s,"case-folded")||strstr(s,"safe directory"))DIAG("PATH","Paketin dosya yolları veya hedef dizin güvenlik kontrolünü geçmedi. Ayrıntılardaki nedeni kontrol et.");
 if(strstr(s,"param.sfo")||strstr(s,"content ID")||strstr(s,"base game or update")||strstr(s,"update version")||strstr(s,"metadata")||strstr(s,"Metadata")||strstr(s,"eboot.bin"))DIAG("METADATA","Oyun bilgileri eksik, uyuşmuyor veya paket türü desteklenmiyor. PS4 ana oyun ve güncelleme paketleri kabul edilir.");
 if(strstr(s,"PFSC")||strstr(s,"PFS")||strstr(s,"pfs_image.dat"))DIAG("LAYOUT","Paketin veri yapısı çözülemedi. Yapı desteklenmiyor, eksik veya bozuk olabilir; ayrıntılarda başarısız kontrol yazıyor.");
 if(strstr(s,"allocation")||strstr(s,"buffer"))DIAG("MEMORY","Çıkarma için gereken bellek ayrılamadı. İşlem tamamlanmadı.");
 DIAG("EXTRACT","Çıkarma tamamlanamadı. Kaynak paket, hedef erişimi ve disk bağlantısını kontrol et; kesin kontrol adı teknik ayrıntılarda.");
#undef DIAG
}
#endif
