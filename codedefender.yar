rule CodeDefender {
    meta:
        description = "CodeDefender Signature (BELabs)"
        author = "Libalpm64"
        date = "2025"
        severity = "High"
        category = "Obfuscation"
        confidence = "High"
    
    strings:
        // movdqu, movdqu, movdqu
        $pattern1 = {66 0F E7 ?? ?? ?? ?? ?? 66 0F E7 ?? ?? ?? ?? ?? 66 0F E7 ?? ?? ?? ?? ??}
        
        // phminposuw, movmskpd
        $pattern2 = {66 0F 38 41 ?? 66 0F 50} 
        
        // extractps, movmskpd, movq
        $pattern3 = {66 0F C5 ?? ?? 66 0F 50 ?? ?? ?? ?? 66 0F 7E} 
        
        // pmovmskb, paddq
        $pattern4 = {66 0F D7 ?? ?? ?? ?? ?? 66 0F D4} 
        
         // [rsp+10h] -> [rsp+20h]
        $pattern5 = {66 0F E7 ?? 10 ?? ?? ?? 66 0F E7 ?? 20}
        
    condition:
        $pattern1 or $pattern2 or $pattern3 or $pattern4 or $pattern5
}