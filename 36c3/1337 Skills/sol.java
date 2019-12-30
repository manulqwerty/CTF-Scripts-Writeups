import java.util.Calendar;

class Solver{  
    public static void main(String args[]){
        Calendar instance = Calendar.getInstance();
        System.out.printf("Activation Code: %d\n", ((int) (Math.pow((double) (instance.get(3) * instance.get(1)), 2.0d) % 999983.0d)));  
    }
}