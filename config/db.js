const mongoose = require('mongoose')


const connectToDatabase = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URL, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log('DB CONNECTED');
  } catch (error) {
    console.error('UNABLE to connect to DB:', error.message);
  }
};

module.exports = connectToDatabase;