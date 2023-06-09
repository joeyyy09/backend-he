const express = require("express");
const uuid = require("uuid");
const bcrypt = require("bcrypt");

const app = express();
app.use(express.json());

// In-memory data store
const students = [];
const deans = [];
const sessions = [];

// Middleware to validate bearer token
function validateToken(req, res, next) {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).json({ message: "Missing token" });
  }

  const student = students.find((student) => student.token === token);
  const dean = deans.find((dean) => dean.token === token);

  if (!student && !dean) {
    return res.status(401).json({ message: "Invalid token" });
  }

  req.user = student || dean;
  next();
}

// Helper function to hash passwords
function hashPassword(password) {
  const salt = bcrypt.genSaltSync(10);
  return bcrypt.hashSync(password, salt);
}

// Student login - Get token
app.post("/students/login", (req, res) => {
  const { universityId, password } = req.body;
  // Authenticate student
  const student = students.find(
    (student) => student.universityId === universityId
  );
  if (!student || !bcrypt.compareSync(password, student.password)) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  // Generate and return token
  const token = uuid.v4();
  student.token = token;
  res.json({ token });
});

// Get list of free sessions
app.get("/sessions", validateToken, (req, res) => {
  // Check if it's Thursday or Friday at 10 AM
  const currentTime = new Date();
  if (currentTime.getDay() !== 4 || currentTime.getHours() !== 10) {
    return res
      .status(403)
      .json({
        message: "Sessions available only on Thursdays and Fridays at 10 AM",
      });
  }

  // Return list of sessions
  res.json({ sessions });
});

// Student books a session
app.post("/sessions/book", validateToken, (req, res) => {
  const { sessionId } = req.body;
  const session = sessions.find((session) => session.id === sessionId);
  if (!session) {
    return res.status(404).json({ message: "Session not found" });
  }
  if (session.student) {
    return res.status(400).json({ message: "Session already booked" });
  }

  // Book the session for the student
  session.student = req.user;
  res.json({ message: "Session booked successfully" });
});

// Dean login - Get token
app.post("/deans/login", (req, res) => {
  const { universityId, password } = req.body;
  // Authenticate dean
  const dean = deans.find((dean) => dean.universityId === universityId);
  if (!dean || !bcrypt.compareSync(password, dean.password)) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  // Generate and return token
  const token = uuid.v4();
  dean.token = token;
  res.json({ token });
});

// Get list of pending sessions for dean
app.get("/deans/sessions", validateToken, (req, res) => {
  const pendingSessions = sessions.filter((session) => !session.student);
  res.json({ sessions: pendingSessions });
});

// Student B login - Get token
app.post("/students-b/login", (req, res) => {
  const { universityId, password } = req.body;
  // Authenticate student B
  const student = students.find(
    (student) => student.universityId === universityId
  );
  if (!student || !bcrypt.compareSync(password, student.password)) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  // Generate and return token
  const token = uuid.v4();
  student.token = token;
  res.json({ token });
});

// Student B gets list of free sessions and books a slot
app.post("/students-b/sessions/book", validateToken, (req, res) => {
  const { sessionId } = req.body;
  const session = sessions.find((session) => session.id === sessionId);
  if (!session) {
    return res.status(404).json({ message: "Session not found" });
  }
  if (session.student) {
    return res.status(400).json({ message: "Session already booked" });
  }

  // Book the session for student B
  session.student = req.user;
  res.json({ message: "Session booked successfully" });
});

// Dean gets list of pending sessions after A and B booked
app.get("/deans/sessions/pending", validateToken, (req, res) => {
  const pendingSessions = sessions.filter((session) => !session.student);
  res.json({ sessions: pendingSessions });
});

// Dean gets list of sessions after A's slot time has passed
app.get("/deans/sessions/after-time", validateToken, (req, res) => {
  const currentTime = new Date(); // Simulating current time
  const passedSessions = sessions.filter(
    (session) => session.startTime <= currentTime
  );
  res.json({ sessions: passedSessions });
});

// Populate initial student and dean data
const hashedPassword = hashPassword("password"); // Replace 'password' with actual passwords
students.push({ universityId: "studentA", password: hashedPassword });
students.push({ universityId: "studentB", password: hashedPassword });
deans.push({ universityId: "deanA", password: hashedPassword });

// Start the server
app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
