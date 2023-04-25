//选民将自己的硬币进行铸币承诺   
    public  static  String comm(String o){
        String comm = SecureUtil.sha256(o);
        return comm;
    }