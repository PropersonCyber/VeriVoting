//A0为候选人第一部分的聚合秘钥，sk为候选人的私钥
    public static double[] sig(double[] A0 , double sk){
        double[] dk = new double[3];
        for (int i = 0; i < 3; i++){
             dk[i] = Math.pow(A0[i], sk);
        }
        return dk;
    }