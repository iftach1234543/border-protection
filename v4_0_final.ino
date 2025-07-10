// Motor driver pins (TB6612)
#define PIN_Motor_PWMA 5
#define PIN_Motor_PWMB 6
#define PIN_Motor_AIN_1 7
#define PIN_Motor_BIN_1 8
#define PIN_Motor_STBY 3

// Ultrasonic sensor pins
#define TRIG_PIN 13
#define ECHO_PIN 12

// Distance threshold (cm)
#define OBSTACLE_DISTANCE 20

// Line tracking sensor pins
#define SENSOR_LEFT   A0
#define SENSOR_MIDDLE A1
#define SENSOR_RIGHT  A2

#define SPEED 70  // Base speed (0-255)

// Helper macros (assuming LOW means line detected)
#define LT_L (digitalRead(SENSOR_LEFT) == LOW)
#define LT_M (digitalRead(SENSOR_MIDDLE) == LOW)
#define LT_R (digitalRead(SENSOR_RIGHT) == LOW)

bool did_stop = false;
int stop_num = 4;
int num = 1;



// Ultrasonic distance function
int Distance_test() {
  digitalWrite(TRIG_PIN, LOW);   
  delayMicroseconds(2);
  digitalWrite(TRIG_PIN, HIGH);  
  delayMicroseconds(10);  // 10us pulse
  digitalWrite(TRIG_PIN, LOW);   
  unsigned long duration = pulseIn(ECHO_PIN, HIGH);
  int distance_cm = duration / 58;
  return (distance_cm > 200) ? 200 : distance_cm;
}

void setVoltageForDuration(float targetVoltage) {
  // Validate input voltage range (0-5V)
  if (targetVoltage < 0.0) {
    targetVoltage = 0.0;
  } else if (targetVoltage > 5.0) {
    targetVoltage = 5.0;
  }
  
  // Convert voltage to PWM value (0-255)
  int pwmValue = (int)((targetVoltage / 5.0) * 255 + 0.5); // +0.5 for rounding
  
  // Set pin 11 as output
  pinMode(11, OUTPUT);
  int i = 0;
  while(i!=600)  {
      digitalWrite(11, HIGH);
  
      // Maintain voltage for 5 seconds
      delay(3);
      // Optional: Turn off the output after duration
      digitalWrite(11, LOW);
      delay(2);
      i++;



  }
  
  // Apply the PWM signal
}

void driveMotors(bool dirA, int speedA, bool dirB, int speedB) {
  digitalWrite(PIN_Motor_AIN_1, dirA ? HIGH : LOW);
  digitalWrite(PIN_Motor_BIN_1, dirB ? HIGH : LOW);
  analogWrite(PIN_Motor_PWMA, speedA);
  analogWrite(PIN_Motor_PWMB, speedB);
}

void stopMotors() {
  analogWrite(PIN_Motor_PWMA, 0);
  analogWrite(PIN_Motor_PWMB, 0);
}

void forward() {
  driveMotors(true, SPEED, true, SPEED);
  Serial.println("Forward");
}

void left() {
  // Pivot left: left wheel backward, right wheel forward
  driveMotors(false, SPEED, true, SPEED);
  Serial.println("Pivot Left");
}

void right() {
  // Pivot right: left wheel forward, right wheel backward
  driveMotors(true, SPEED, false, SPEED);
  Serial.println("Pivot Right");
}

void stop_and_kill() {
  unsigned long rotate_start, rotate_duration;
  int distance;

  // 1. Rotate left until obstacle is detected


  rotate_start = millis();
  while (true) {
    right();
    distance = Distance_test();
    Serial.print("Distance: ");
    Serial.println(distance);
    if (distance <= OBSTACLE_DISTANCE) {
      stopMotors();
      break;
    }
    delay(50); // Small delay to avoid spamming sensor
  }
  rotate_duration = millis() - rotate_start;
  delay(300);

  // 2. Stop for 5 seconds
  Serial.println("Obstacle detected. Stopping for 5 seconds...");
  stopMotors();
  setVoltageForDuration(3);
  

  // 3. Rotate right for the same time to return to original heading
  Serial.println("Returning to starting position...");
  rotate_start = millis();
  while (millis() - rotate_start < rotate_duration) {
    left();
    delay(10);
  }
  stopMotors();
  Serial.println("Returned to starting position.");
  delay(300);

  // End program (do nothing)
  while (true) {
    stopMotors();
    delay(1000);
  }
}


void setup() {
  // Motor pins
  pinMode(PIN_Motor_STBY, OUTPUT);
  pinMode(PIN_Motor_PWMA, OUTPUT);
  pinMode(PIN_Motor_PWMB, OUTPUT);
  pinMode(PIN_Motor_AIN_1, OUTPUT);
  pinMode(PIN_Motor_BIN_1, OUTPUT);
  digitalWrite(PIN_Motor_STBY, HIGH); // Enable motors

  // Sensor pins
  pinMode(SENSOR_LEFT, INPUT);
  pinMode(SENSOR_MIDDLE, INPUT);
  pinMode(SENSOR_RIGHT, INPUT);

  // Ultrasonic pins
  pinMode(TRIG_PIN, OUTPUT);
  pinMode(ECHO_PIN, INPUT);

  Serial.begin(9600);
  while (!Serial.available()) {

  }
  char t = Serial.read();
  stop_num = t;
}



void loop() {
  // Read sensors
  bool leftSensor = LT_L;
  bool middleSensor = LT_M;
  bool rightSensor = LT_R;

  // Line tracking logic
  if (!middleSensor) {
    did_stop = false;
    forward(); // On track
  } else if (!rightSensor) {
    did_stop = false;
    right(); // Too far left, pivot right
  } else if (!leftSensor) {
    did_stop = false;
    left(); // Too far right, pivot left
  }  else {
    if (!did_stop) {
      did_stop = true;
      stopMotors(); // Lost line, stop
      delay(1000);
      Serial.println("Stop/Lost");
      if(stop_num == num) {
        stop_and_kill();
      }
      num ++;

    }
    
  }

}
