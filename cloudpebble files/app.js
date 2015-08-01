var UI = require('ui');
var ajax = require('ajax');
var Vector2 = require('vector2');


/* TODO: eventually we should load all the stops dynamically */
var getMenuItems = function() {
  var items = [];
    // Add to menu items array
  items.push({
      title:'Euclid Hts\n & Derbyshire',
      subtitle:'7 East 89th-Euclid',
      stop_id:1
  });
    
  items.push({
      title:'Euclid Hts &\n Lennox',
      subtitle:'7 Richmond',
      stop_id:2
  });
  
  items.push({
      title:'Cedar & Norfolk',
      subtitle:'32 East 89th-Euclid',
      stop_id:5
  });
  
  items.push({
      title:'Cedar & Norfolk',
      subtitle:'32 Montefiore',
      stop_id:3
  });
  // Finally return whole array
  return items;
};

// Show splash screen while waiting for data
var splashWindow = new UI.Window();

// Text element to inform user
var text = new UI.Text({
  position: new Vector2(0, 0),
  size: new Vector2(144, 168),
  text:'Downloading weather data...',
  font:'GOTHIC_28_BOLD',
  color:'black',
  textOverflow:'wrap',
  textAlign:'center',
	backgroundColor:'white'
});

var menuItems = getMenuItems();
var stopsMenu = new UI.Menu({
      sections: [{
        title: 'Current stops',
        items: menuItems
      }]
    });

stopsMenu.on('select', function(e) {
  console.log(menuItems[e.itemIndex].title);
  console.log(menuItems[e.itemIndex].subtitle);
  console.log(menuItems[e.itemIndex].stop_id);
  var stop_id = menuItems[e.itemIndex].stop_id;
  ajax(
   {
    url:'http://bus.debbyandrob.com/api/prediction?stop=' + stop_id ,
    type:'json'
  },
  function(data) {
    console.log(data);
    var subtitle = '';
    var content = '';
    
    if (data['predicted'] !== null)
    {
      subtitle = data['prediction']; 
      content= 'scheduled: (' + data['scheduled'] + ')';
    }
    else
    {
      subtitle = data['scheduled'];
      content= 'no prediction available, showing scheduled';
    }
    
    var detailCard = new UI.Card({
      title:data['minutes_until_bus'] + ' minutes',
      subtitle:subtitle,
      body:content
    });
    console.log('showing detail card', detailCard);
    detailCard.show();
  },
  function(error) {
          console.log('Ajax Call failed: ' + error);
  }
  );
    
    
  
});

// Get that forecast
  /*
  var forecast = data.list[e.itemIndex];

  // Assemble body string
  var content = data.list[e.itemIndex].weather[0].description;

  // Capitalize first letter
  content = content.charAt(0).toUpperCase() + content.substring(1);

  // Add temperature, pressure etc
  content += '\nTemperature: ' + Math.round(forecast.main.temp - 273.15) + '°C' 
  + '\nPressure: ' + Math.round(forecast.main.pressure) + ' mbar' +
    '\nWind: ' + Math.round(forecast.wind.speed) + ' mph, ' + 
    Math.round(forecast.wind.deg) + '°';

      // Create the Card for detailed view
      var detailCard = new UI.Card({
        title:'Details',
        subtitle:e.item.subtitle,
        body: content
      });
      detailCard.show();
    */


stopsMenu.show();
// Add to splashWindow and show
/*splashWindow.add(text);
splashWindow.show();*/

// Make request to openweathermap.org
/*
ajax(
  {
    url:'http://api.openweathermap.org/data/2.5/forecast?q=Cleveland,OH',
    type:'json'
  },
  function(data) {
    // Create an array of Menu items
    

    // Construct Menu to show to user
    var resultsMenu = new UI.Menu({
      sections: [{
        title: 'Current Forecast',
        items: menuItems
      }]
    });

    // Add an action for SELECT

    // Show the Menu, hide the splash
    resultsMenu.show();
    splashWindow.hide();
    
    // Register for 'tap' events
    resultsMenu.on('accelTap', function(e) {
      // Make another request to openweathermap.org
      ajax(
        {
          url:'http://api.openweathermap.org/data/2.5/forecast?q=London',
          type:'json'
        },
        function(data) {
          // Create an array of Menu items
          var newItems = parseFeed(data, 10);
          
          // Update the Menu's first section
          resultsMenu.items(0, newItems);
          
          // Notify the user
          Vibe.vibrate('short');
        },
        function(error) {
          console.log('Download failed: ' + error);
        }
      );
    });
  },
  function(error) {
    console.log("Download failed: " + error);
  }
);
*/

