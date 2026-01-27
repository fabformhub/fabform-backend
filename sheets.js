const {google} = require('googleapis');

async function save(spreadsheetId, values) {

const auth = new google.auth.GoogleAuth({
  keyFile: 'keys.json',
  scopes: ['https://www.googleapis.com/auth/spreadsheets'],
});	

 const authClientObject = await auth.getClient();
 const googleSheetsInstance = google.sheets({ version: "v4", auth: authClientObject });

 await googleSheetsInstance.spreadsheets.values.append({
        auth, //auth object
        spreadsheetId, //spreadsheet id
        range: "Sheet1!A:B", //sheet name and range of cells
        valueInputOption: "USER_ENTERED", // The information will be passed according to what the usere passes in as date, number or text
        resource: {
           values: [values],
        },
    });
}

module.exports.save = save
