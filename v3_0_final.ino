//www.elegoo.com
#include <Servo.h>
Servo myservo;

//Line Tracking IO define
#define LT_R !digitalRead(10)
#define LT_M !digitalRead(4)
#define LT_L !digitalRead(2)

#define ENA 5
#define ENB 6
#define IN1 7
#define IN2 8
#define IN3 9
#define IN4 11
int rightDistance = 0, leftDistance = 0, middleDistance = 0;

#define distance_cm 20


int Echo = A4;  
int Trig = A5; 

char stop_num = 0;
char nothing = 255;
bool is_white = false;
bool next_stop = false;
bool stop_at_two = false; 

#define carSpeed 120

void forward(){
  analogWrite(ENA, carSpeed);
  analogWrite(ENB, carSpeed);
  digitalWrite(IN1, HIGH);
  digitalWrite(IN2, LOW);
  digitalWrite(IN3, LOW);
  digitalWrite(IN4, HIGH);
}

void back(){
  analogWrite(ENA, carSpeed);
  analogWrite(ENB, carSpeed);
  digitalWrite(IN1, LOW);
  digitalWrite(IN2, HIGH);
  digitalWrite(IN3, HIGH);
  digitalWrite(IN4, LOW);
}

void left(){
  analogWrite(ENA, carSpeed);
  analogWrite(ENB, carSpeed);
  digitalWrite(IN1, LOW);
  digitalWrite(IN2, HIGH);
  digitalWrite(IN3, LOW);
  digitalWrite(IN4, HIGH);
}

void right(){
  analogWrite(ENA, carSpeed);
  analogWrite(ENB, carSpeed);
  digitalWrite(IN1, HIGH);
  digitalWrite(IN2, LOW);
  digitalWrite(IN3, HIGH);
  digitalWrite(IN4, LOW); 
} 

void stop(){
   digitalWrite(ENA, LOW);
   digitalWrite(ENB, LOW);
} 

int Distance_test() {
  digitalWrite(Trig, LOW);   
  delayMicroseconds(2);
  digitalWrite(Trig, HIGH);  
  delayMicroseconds(20);
  digitalWrite(Trig, LOW);   
  float Fdistance = pulseIn(Echo, HIGH);  
  Fdistance= Fdistance / 58;       
  return (int)Fdistance;
}  

char Full_distance() {
  int n = 90;
  myservo.write(n);
  int min_dis = 100;
  char deg = 0;
  int temp = 0;
  for (int i =0; i<22; i++) {
    temp = Distance_test();
    if (temp <= distance_cm) {
      if (temp< min_dis) {
      min_dis = temp;
      deg = n;
      }
    }
    n += 5;
    myservo.write(n);
    delay(100);
    

  }
  if (min_dis == 100) {
    deg = 0;
  }
  myservo.write(90);
  delay(100);
  return deg;
}

void setup(){
  myservo.attach(3,700,2400);  // attach servo on pin 3 to servo object

  Serial.begin(9600);
  pinMode(Echo, INPUT);    
  pinMode(Trig, OUTPUT);  
  pinMode(10,INPUT);
  pinMode(4,INPUT);
  pinMode(2,INPUT);
  myservo.write(90);
  while (!Serial.available()) {

  }
  char t = Serial.read();
 
}

void loop() {
  if(LT_M){
    is_white = false;
    forward();
  }
  else if(LT_R) { 
    is_white = false;
    right();

  }   
  else if(LT_L) {
    is_white = false;
    left();

  }
  else {
    
    if (!is_white) {
      stop();
      is_white = true;
      stop_num = stop_num + 1;
      if (next_stop) {
        next_stop = false;
        while(!Serial.available()) {

        }        
      }
      }

      if (stop_num != 5) {
        middleDistance = Full_distance();
        if(middleDistance != 0) {
          Serial.write(stop_num);
          delay(500);
          Serial.write(middleDistance);
          next_stop = true;
        } 

      }
      

      if (stop_num == 5) {
        stop_num = 0;
        delay(1000);
      }

      
      

    }
      

      
      
  }
  
}

