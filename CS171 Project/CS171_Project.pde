import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import controlP5.*;

ControlP5 cp5;
Textarea myTextarea; // Text area for more info
Button myButton; // Button to enable/disable area for more info
Table table;
static String day = ""; // Setting day as a global variable
static String textArea_text = ""; // Setting textArea_text as a global variable
static String textArea_text_visible = ""; // Setting textArea_visible as a global variable
static String button_label = "More Info"; // Setting button_label as a global variable

void setup() 
{
  size(700,400);
  background(0);
  
  cp5 = new ControlP5(this);
  
  //This "More Info" button will be used to show the text area when clicked, and hide it when clicked again
  myButton = cp5.addButton("moreInfo")
     .setPosition(10,100)
     .setSize(100,19)
     ;
  //The text output for the "More Info" button
  myTextarea = cp5.addTextarea("txt")
                  .setPosition(10,119)
                  .setSize(400,200)
                  .setFont(createFont("arial",12))
                  .setLineHeight(14)
                  .setColor(color(128))
                  .setColorBackground(color(0,0))
                  .setColorForeground(color(0,0));
                  ;
  
  LocalDate date = LocalDate.now(); // Getting today's date
  int saved_i = 0; // Will be used to determine the most amount of wind out of every day
  int MAX_DAYS_TO_LOOK_FORWARD = 3; // Not to be more than 5, they do not predict past 5 days
  
  float LargestForecastWindMean = 0; // To store the largest mean/average value
  for(int i = 0; i < MAX_DAYS_TO_LOOK_FORWARD; i++)
  {
    date = date.plusDays(1); // Looking forward one day each iteration
    
    String s_date = date.format(DateTimeFormatter.ofPattern("dd-MMM-yyyy")); //Formatting the date properly for the url
    String url = "https://www.smartgriddashboard.com/DashboardService.svc/csv?area=windActual&region=ALL&datefrom="+s_date+"%2000:00&dateto="+s_date+"%2023:59";
    // Getting the url which 

      table = loadTable(url, "header, csv"); //Will be loadTable(url, "header");
      // If the smartgrid website is down (it did go down once during the creation of this project), it should be handled
    if(table == null) // Try catch would not work as loadTable handles the exception and sets its value to null instead
    {
      day = "Smartgrid website is down";
      println(day);
      return;
    }
    // Adding all of the values from midnight to 6am in the table, dividing them by 25 to get the mean/average
    float ForecastWindAllVal = 0;
    for(int col = 1; col < 26; col++)
    { 
      float ForecastWindVal = table.getFloat(i," FORECAST WIND(MW)");
      ForecastWindAllVal += ForecastWindVal;
    }
    float ForecastWindMean = ForecastWindAllVal/25;
    
    if(ForecastWindMean > LargestForecastWindMean)
    {
      saved_i = i; // Hold the day of ForecastWindMean
      LargestForecastWindMean = ForecastWindMean; // Hold the value of ForecastWindMean
    }
    String real_date = date.format(DateTimeFormatter.ofPattern("dd/MM/yyyy")); // Creating a more legible date to show in the output
    textArea_text_visible += "The predicted mean wind energy that will be generated on " + real_date +" between midnight and 6:00 is: " + int(ForecastWindMean) +" MW\n"; // Casting ForecastWindMean to an int to remove the .0 value at the end
  }
  if(saved_i == 0)
  {
    day = "Tonight";
  }
  else if(saved_i == 1)
  {
    day = "Tomorrow night";
  }
  else
  {
    day = saved_i+" days from now";
  }
  // If you wanted to get the answer in the terminal you could uncomment the line below:
  // println("You should charge your vehicle "+day+" as the forecast wind for that night is: "+int(LargestForecastWindMean)+" MW");
}
void draw()
{
  // Code adapted from https://processing.org/reference/textFont_.html
  // Creating and formatting the output text
  String text = "You should charge your vehicle:";
  PFont mono;
  mono = createFont("andalemo.ttf",128);
  //textSize(20);
  textFont(mono,14);
  text(text,10,40);
  textSize(35);
  // If the best day to charge is tonight it will be green instead of white :)
  if(day.equals("Tonight"))
  {
    fill(0,255,0); //Change text to green
  }
  text(day,10,70);
  fill(255); //Reset text to white
  
  myTextarea.setText(textArea_text); // Set the text area to what has been defined in moreInfo()
  myButton.setLabel(button_label); // Set the button label to what has been defined in moreInfo()
}

public void moreInfo() // Called when the button is pressed
{
  if(textArea_text == textArea_text_visible) // If the user already pressed the button
  {
    textArea_text = ""; // Hide the text
    button_label = "More Info"; // Change the button label back to "More Info"
  }
  else
  {
    textArea_text = textArea_text_visible; // Make the text visible
    button_label = "Less Info"; // Change the button label to "Less Info"
  }
}
