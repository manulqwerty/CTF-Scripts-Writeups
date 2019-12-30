# 1337 Skills
```
App: https://play.google.com/store/apps/details?id=com.progressio.wildskills
Connection: nc 88.198.154.132 7002
```

This is an Android reversing challenge. We can download the [apk here.](https://apkpure.com/es/wild-skills/com.progressio.wildskills)
The app request an activation code to start using it. Let's dissasembly the apk in other to get those codes.

## JADX

Let's open the apk with [jadx.](https://github.com/skylot/jadx)
In the **MainActivity** we see this function:
```java
public void activateApp(View view) {
    int i;
    try {
        i = Integer.parseInt(this.editTextActivation.getText().toString());
    } catch (NumberFormatException unused) {
        i = -1;
    }
    Calendar instance = Calendar.getInstance();
    if (i == ((int) (Math.pow((double) (instance.get(3) * instance.get(1)), 2.0d) % 999983.0d))) {
        findViewById(R.id.scrollViewActivation).setVisibility(4);
        ((InputMethodManager) getSystemService("input_method")).hideSoftInputFromWindow(this.editTextActivation.getWindowToken(), 0);
        SharedPreferences.Editor edit = this.prefsmain.edit();
        edit.putBoolean("Activated", true);
        long time = new Date().getTime();
        edit.putLong("Installed", time);
        edit.putLong("ActivationDate", time);
        edit.commit();
        return;
    }
    Toast.makeText(this, "Ungültiger Aktivierungscode", 1).show();
    this.editTextActivation.requestFocus();
    ((InputMethodManager) getSystemService("input_method")).showSoftInput(this.editTextActivation, 1);
}
```
> Activation Code: `((int) (Math.pow((double) (instance.get(3) * instance.get(1)), 2.0d) % 999983.0d))`

We can decode it with this code:
```java
import java.util.Calendar;

class Solver{  
    public static void main(String args[]){
        Calendar instance = Calendar.getInstance();
        System.out.printf("Activation Code: %d\n", ((int) (Math.pow((double) (instance.get(3) * instance.get(1)), 2.0d) % 999983.0d)));  
    }
}
```
```bash
» javac sol.java
» java Solver
Activation Code: 76429
```

Now we get the rest of codes in the function `courseActivation(View view)`:
```java
[...]
if (obj.equals("sgk258"))
[...]
if (obj.equals("wmt275"))
[...]
if (obj.equals("udh736"))
[...]
```

Now, let's get the flag:
```bash
» nc 88.198.154.132 7002
Activation code:
76429
activated!
Sales activation code:
sgk258
activated!
Leadership activation code:
wmt275
activated
Service Roadmap (SRM) activation code:
udh736
activated!
Congratulations please give me your name:
Manu
   ______________________________
 / \                             \.
|   |                            |.
 \_ |                            |.
    | Certificate of Attendance  |.
    |                            |.
    |  This is to certify that   |.
    |                            |.
    |            Manu            |.
    |                            |.
    |        has attended        |.
    |                            |.
    | **The baby rev challenge** |.
    |                            |.
    |                            |.
    |                       hxp  |.
    |                            |.
    | -------------------------- |.
    |                            |.
    |hxp{thx_f0r_4773nd1n6_70d4y}|.
    |                            |.
    |   _________________________|___
    |  /                            /.
    \_/____________________________/.

```
