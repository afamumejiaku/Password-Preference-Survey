from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import os
import random
import string
from collections import Counter
from math import sqrt, log2
from zxcvbn import zxcvbn
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv

app = Flask(__name__)
# Ensure the secret key is set for sessions
app.secret_key = 'your_secret_key'
# Configure SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///survey.db'  # SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Initialize SQLAlchemy
db = SQLAlchemy(app)
# Define database model for survey responses
class SurveyResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, nullable=False)
    question_text = db.Column(db.String(255), nullable=False)
    answer = db.Column(db.String(255), nullable=False)
#Credentials
class UserCredentials(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    long_password = db.Column(db.String(255), nullable=False)
    short_password = db.Column(db.String(50), nullable=False)
#Demographics
class Demographics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    age_group = db.Column(db.String(20), nullable=False)
    employment_status = db.Column(db.String(100), nullable=False)
    race = db.Column(db.String(50), nullable=False)
#Password feedback
# Add to models in app.py
class PasswordFeedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password_type = db.Column(db.String(255), nullable=False)  # Type of password (e.g., long, short, etc.)
    password_value = db.Column(db.String(255), nullable=False)
    memorable_rating = db.Column(db.String(50), nullable=False)  # How memorable is the password
    usability_rating = db.Column(db.String(50), nullable=False)  # How likely to use in real life
    password_log_guesses = db.Column(db.Float, nullable=True)  # Log guesses (if applicable)
    password_entropy = db.Column(db.Float, nullable=True)  # Entropy (if applicable)
    password_similarity = db.Column(db.Float, nullable=True)  # Similarity score

# Questions for the survey
QUESTIONS = [
    {"id": 1, "question": "Do you consider your password usage safe?", "type": "dropdown", "options": ["Very Safe", "Somewhat Safe", "Not Very Safe", "Not Safe at All"]},
    {"id": 2, "question": "Would you prefer a new password technology that requires two passwords but eliminates the need to ever change passwords again?", "type": "dropdown", "options": ["Definitely Yes", "Probably Yes", "Probably No", "Definitely No"]},
    {"id": 3, "question": "Do you reuse passwords across multiple platforms?", "type": "dropdown", "options": ["Always", "Sometimes", "Rarely", "Never"]},
    {"id": 4, "question": "Do you use passwords with 12 or more characters?", "type": "dropdown", "options": ["Always", "Frequently", "Occasionally", "Never"]},
    {"id": 5, "question": "Do you find it frustrating when websites have different rules for creating passwords? \n Requiring different mix of lowercase and uppercase letters, numbers, and special characters?", "type": "dropdown", "options": ["Extremely Burdensome", "Somewhat Burdensome", "Not Very Burdensome", "Not a Burden at All"]},
    {"id": 6, "question": "Do you share your passwords with others?", "type": "dropdown", "options": ["Never", "Rarely", "Sometimes", "Always"]},
    {"id": 7, "question": "Would you consider paying for password managers?", "type": "dropdown", "options": ["Definitely Yes", "Probably Yes", "Probably No", "Definitely No"]},
    {"id": 8, "question": "Do you use password managers or store passwords on any physical device?", "type": "dropdown", "options": ["Always", "Frequently", "Occasionally", "Never"]},
    {"id": 9, "question": "Do you consider the use of multifactor authentication a waste of time?", "type": "dropdown", "options": ["Strongly Disagree", "Disagree", "Agree", "Strongly Agree"]},
    {"id": 10, "question": "Do you dislike how often you are required to update passwords across websites?", "type": "dropdown", "options": ["Strongly Dislike", "Somewhat Dislike", "Neutral", "Not at All"]},
    {"id": 11, "question": "Do you wish for a device, like your phone, that can sign you into all your accounts?", "type": "dropdown", "options": ["Definitely Yes", "Probably Yes", "Probably No", "Definitely No"]},
    {"id": 12, "question": "Would you like to use a service like email or Microsoft to sign into all your accounts?", "type": "dropdown", "options": ["Definitely Yes", "Probably Yes", "Probably No", "Definitely No"]},
    {"id": 13, "question": "Do you wish passwords could be created and stored in a way where the website or service cannot see or know your password and would never require you to update it?", "type": "dropdown", "options": ["Definitely Yes", "Probably Yes", "Probably No", "Definitely No"]}
]
# Replace all vowels with random characters
def replace_vowels_with_random(password):
    vowels = "aeiouAEIOU"
    random_chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(random_chars) if char in vowels else char for char in password)
# Replace only the mode vowel with random characters
def replace_mode_vowel_with_random(password):
    vowels = "aeiouAEIOU"
    random_chars = string.ascii_letters + string.digits + string.punctuation
    vowel_counts = Counter(char for char in password if char in vowels)
    if not vowel_counts:
        return password  # No vowels to replace
    mode_vowel = vowel_counts.most_common(1)[0][0]
    return ''.join(random.choice(random_chars) if char == mode_vowel else char for char in password)
# Add a four-character mnemonic chunk from the words list
def add_mnemonic_chunk(password, words):
    mnemonic_chunk = ''.join(word[0] for word in words[:4] if word)[:4]  # First 4 words' first letters
    return password + mnemonic_chunk
# Replace mode vowel and add mnemonic chunk
def replace_mode_vowel_and_add_mnemonic(password, words):
    password = replace_mode_vowel_with_random(password)
    return add_mnemonic_chunk(password, words)
# Replace all vowels with a mnemonic chunk
def replace_vowels_with_mnemonic(password, words):
    vowels = "aeiouAEIOU"
    mnemonic_chunk = ''.join(word[0] for word in words[:4] if word)[:4]  # First 4 words' first letters
    iterator = iter(mnemonic_chunk)
    return ''.join(next(iterator, char) if char in vowels else char for char in password)
#Calculate Cosine Similarity
def cosine_similarity(str1, str2):
    # Tokenize the strings
    vec1 = Counter(str1)
    vec2 = Counter(str2)

    # Calculate dot product
    dot_product = sum(vec1[char] * vec2[char] for char in set(vec1) & set(vec2))

    # Calculate magnitudes
    magnitude1 = sqrt(sum(val ** 2 for val in vec1.values()))
    magnitude2 = sqrt(sum(val ** 2 for val in vec2.values()))

    # Handle division by zero
    if not magnitude1 or not magnitude2:
        return 0.0

    return round(dot_product / (magnitude1 * magnitude2), 2)
#Calculate Levenshtein Distance
def levenshtein_distance(str1, str2):
    m, n = len(str1), len(str2)

    # Initialize DP table
    dp = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(m + 1):
        for j in range(n + 1):
            if i == 0:
                dp[i][j] = j  # Insert all characters of str2
            elif j == 0:
                dp[i][j] = i  # Remove all characters of str1
            elif str1[i - 1] == str2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]  # No cost
            else:
                dp[i][j] = 1 + min(dp[i - 1][j],  # Remove
                                   dp[i][j - 1],  # Insert
                                   dp[i - 1][j - 1])  # Replace

    return dp[m][n]
#Calculate Entropy
def entropy(string):
    length = len(string)
    if length == 0:
        return 0.0

    # Count character frequencies
    char_counts = Counter(string)

    # Calculate entropy
    return round(-sum((count / length) * log2(count / length) for count in char_counts.values()), 2)
#Calculate ZXCVBN Strength
def zxcvbn_strength(password):
    analysis = zxcvbn(password)
    score = analysis['score']  # Score ranges from 0 (weakest) to 4 (strongest)
    time = analysis['crack_times_display']
    answer = get_strength_description(score) + convert_dict_to_statement(time)
    return answer
#calculate ZXCVBN LogGuesses
def zxcvbn_log_guesses(password):
    analysis = zxcvbn(password)
    log_guesses = analysis['guesses_log10']
    return round(log_guesses, 2)
# AI Generated Passwords
def generate_password_with_ai(words):
    word1,word2,word3,word4,word5 = words
    client = OpenAI(
        api_key= os.getenv("OPENAI_API_KEY")
    )
    completion = client.chat.completions.create(
      model="ft:gpt-4o-mini-2024-07-18:personal::AaRpiD6d",
      messages=[
        {"role": "system", "content": "You create users passwords given words."},
        {"role": "user", "content": f"Generate a secure password using the words: {', '.join(words)}"}
      ]
    )
    return(completion.choices[0].message.content)
def generate_strong_password(words):
    # Generate a strong password with log_guesses >= 14
    while True:
        newpassword = generate_password_with_ai(words)
        strength_newpassword = zxcvbn_strength(newpassword)
        log_guesses_newpassword = zxcvbn_log_guesses(newpassword)
        if log_guesses_newpassword >= 14:
            return newpassword, log_guesses_newpassword, strength_newpassword
def get_strength_description(score):
    """
    Map strength score to a descriptive label.
    """
    descriptions = {
        0: "Very Weak ",
        1: "Weak ",
        2: "Fair ",
        3: "Good ",
        4: "Very Strong "
    }
    return descriptions.get(score, "Unknown")
def convert_dict_to_statement(data):
    """
    Convert a dictionary of crack times into a human-readable statement.
    
    Args:
        data (dict): A dictionary where keys are scenario descriptions and values are crack times.
    
    Returns:
        str: A human-readable statement describing the crack times.
    """
    # Define a mapping for simplified scenarios
    scenarios = {
        "online_throttling_100_per_hour": "Online attack (100/hr",
        "online_no_throttling_10_per_second": "10/sec)",
        "offline_slow_hashing_1e4_per_second": "Offline attack (10k/sec",
        "offline_fast_hashing_1e10_per_second": "10B/sec)"
    }

    # Translate dictionary keys using the mapping
    translations = {scenarios[key]: value for key, value in data.items() if key in scenarios}

    # Construct the statement
    statement = (
        f"\n{list(translations.keys())[0]} - {list(translations.keys())[1]} : {translations[list(translations.keys())[0]]} - {translations[list(translations.keys())[1]]}. "
        f"\n{list(translations.keys())[2]} - {list(translations.keys())[3]} : {translations[list(translations.keys())[2]]} - {translations[list(translations.keys())[3]]}. "
    )
    return statement

# Initialize the database if it doesn't already exist
if not os.path.exists('survey.db'):
    with app.app_context():
        db.create_all()
        print("Database created successfully!")



# Home or Index route
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Retrieve demographic data from the form
        age_group = request.form.get('age_group')
        employment_status = request.form.get('employment_status')
        race = request.form.get('race')
        
        # Validate inputs
        if not age_group or not employment_status or not race:
            return "Please complete all demographic fields.", 400

        # Save demographic data to the database
        demographics = Demographics(
            age_group=age_group,
            employment_status=employment_status,
            race=race
        )
        db.session.add(demographics)
        db.session.commit()

        # Redirect to the questions page
        return redirect(url_for('questions'))

    return render_template('index.html')
# Questions route
@app.route('/questions', methods=['GET', 'POST'])
def questions():
    if request.method == 'GET':
        # Fetch the current highest user number from the database
        last_user = UserCredentials.query.order_by(UserCredentials.id.desc()).first()
        
        # Determine the next username
        if last_user:
            next_user_no = last_user.id + 1
        else:
            next_user_no = 1  # Start with user1 if no users exist
        
        username = f"Participant {next_user_no}"  # Format the username

        # Pass the generated username and questions to the template
        return render_template('questions.html', questions=QUESTIONS, username=username)
    
    if request.method == 'POST':
        for question in QUESTIONS:
            answer = request.form.get(str(question['id']))
            if not answer:
                return "All questions must be answered!", 400

            # Save the response to the database
            response = SurveyResponse(
                question_id=question['id'],
                question_text=question['question'],
                answer=answer
            )
            db.session.add(response)

        # Capture optional words/values
        words = [request.form.get(f"word{i}") for i in range(1, 6)]
        words = [word for word in words if word]  # Remove empty values
        print("Words or Values:", words)

        # Capture Long Password and Words List
        # Handle user credentials
        username = request.form.get("username")
        long_password = request.form.get("long_password")
        short_password = request.form.get("short_password")
        words = [request.form.get(f"word{i}") for i in range(1, 6)]
        words = [word for word in words if word]  # Filter out empty values
        if not username or not long_password or not short_password:
            return "All fields in the username/password form must be completed!", 400
        
        # Save credentials (if using database)
        user_credentials = UserCredentials(
            username=username,
            long_password=long_password,
            short_password=short_password
        )
        db.session.add(user_credentials)
        db.session.commit()

        # Perform Operations
        result1 = replace_vowels_with_random(long_password)
        result2 = replace_mode_vowel_with_random(long_password)
        result3 = add_mnemonic_chunk(long_password, words)
        result4 = replace_mode_vowel_and_add_mnemonic(long_password, words)
        result5 = replace_vowels_with_mnemonic(long_password, words)

        # Pass data to feedback page using session
        session['results'] = {
            "long_password":long_password,
            "result1": result1,
            "result2": result2,
            "result3": result3,
            "result4": result4,
            "result5": result5,
            "short_password" : short_password,
            "words" :words
        }
        return redirect(url_for('feedback'))
    

    # Preprocess questions to ensure `id` is a string
    processed_questions = [
    {
        "id": str(q["id"]), 
        "question": q["question"], 
        "type": q["type"],
        "options": q.get("options", [])  # Add this line to preserve options
    }
    for q in QUESTIONS
    ]

    # Pass preprocessed data to the template
    return render_template('questions.html', questions=processed_questions)
# Feedback route
@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
     # Initialize default variables to avoid UnboundLocalError
    result = None
    newpassword = None
    words = []
    long_password = short_password = result1 = result2 = result3 = result4 = result5 = None
    strength1 = strength2 = strength3 = strength4 = strength5 = None
    long_strength = short_strength = None
    log_guesses1 = log_guesses2 = log_guesses3 = log_guesses4 = log_guesses5 = None
    entropy1 = entropy2 = entropy3 = entropy4 = entropy5 = None
    similarity1 = similarity2 = similarity3 = similarity4 = similarity5 = None
    strength_newpassword = None
    log_guesses_newpassword = None
    entropy_newpassword = None
    similarity_newpassword = None
    newpassword= None

    if request.method == 'POST':
        results = session.get('results', {})
        if not results:
            return "Error: No session data available.", 400
        # Extract results from the session
        long_password = results.get("long_password")
        result1 = results.get("result1")
        result2 = results.get("result2")
        result3 = results.get("result3")
        result4 = results.get("result4")
        result5 = results.get("result5")
        short_password = results.get("short_password")
        words = results.get("words", [])
        strength1 = zxcvbn_strength(result1)
        strength2 = zxcvbn_strength(result2)
        strength3 = zxcvbn_strength(result3)
        strength4 = zxcvbn_strength(result4)
        strength5 = zxcvbn_strength(result5)
        long_strength = zxcvbn_strength(long_password)
        short_strength = zxcvbn_strength(short_password)
        log_guesses1 = zxcvbn_log_guesses(result1)
        log_guesses2 = zxcvbn_log_guesses(result2)
        log_guesses3 = zxcvbn_log_guesses(result3)
        log_guesses4 = zxcvbn_log_guesses(result4)
        log_guesses5 = zxcvbn_log_guesses(result5)
        long_log_guesses = zxcvbn_log_guesses(long_password)
        short_log_guesses = zxcvbn_log_guesses(short_password)
        entropy1 = entropy(result1)
        entropy2 = entropy(result2)
        entropy3 = entropy(result3)
        entropy4 = entropy(result4)
        entropy5 = entropy(result5)
        long_entropy = entropy(long_password)
        short_entropy = entropy(short_password)
        similarity1 = cosine_similarity(result1,long_password)
        similarity2 = cosine_similarity(result2,long_password)
        similarity3 = cosine_similarity(result3,long_password)
        similarity4 = cosine_similarity(result4,long_password)
        similarity5 = cosine_similarity(result5,long_password)
        newpassword, log_guesses_newpassword,  strength_newpassword =  generate_strong_password(words)
        entropy_newpassword= entropy(newpassword)
        similarity_newpassword = cosine_similarity(newpassword,long_password)
        
        feedback = [
            {
                "password_type": "long_password",
                "password_value": long_password,
                "memorable_rating": request.form.get("memorable-result_long_password"),
                "usability_rating": request.form.get("usage-result_long_password"),
                "password_log_guesses": long_log_guesses,
                "password_entropy": long_entropy,
                "password_similarity": 1.0,
            },
            {
                "password_type": "short_password",
                "password_value": short_password,
                "memorable_rating": request.form.get("memorable-result_short_password"),
                "usability_rating": request.form.get("usage-result_short_password"),
                "password_log_guesses": short_log_guesses,
                "password_entropy": short_entropy,
                "password_similarity": 1.0,
            },
            {
                "password_type": "result1",
                "password_value": result1,
                "memorable_rating": request.form.get("memorable-result1"),
                "usability_rating": request.form.get("usage-result1"),
                "password_log_guesses": log_guesses1,
                "password_entropy": entropy1,
                "password_similarity": similarity1 or 0.0,
            },
            {
                "password_type": "result2",
                "password_value": result2,
                "memorable_rating": request.form.get("memorable-result2"),
                "usability_rating": request.form.get("usage-result2"),
                "password_log_guesses": log_guesses2,
                "password_entropy": entropy2,
                "password_similarity": similarity2 or 0.0,
            },
            {
                "password_type": "result3",
                "password_value": result3,
                "memorable_rating": request.form.get("memorable-result3"),
                "usability_rating": request.form.get("usage-result3"),
                "password_log_guesses": log_guesses3,
                "password_entropy": entropy3,
                "password_similarity": similarity3 or 0.0,
            },
            {
                "password_type": "result4",
                "password_value": result4,
                "memorable_rating": request.form.get("memorable-result4"),
                "usability_rating": request.form.get("usage-result4"),
                "password_log_guesses": log_guesses4,
                "password_entropy": entropy4,
                "password_similarity": similarity4 or 0.0,
            },
            {
                "password_type": "result5",
                "password_value": result5,
                "memorable_rating": request.form.get("memorable-result5"),
                "usability_rating": request.form.get("usage-result5"),
                "password_log_guesses": log_guesses5,
                "password_entropy": entropy5,
                "password_similarity": similarity5 or 0.0,
            },
            {
                "password_type": "newpassword",
                "password_value": newpassword,
                "memorable_rating": request.form.get("memorable-newpassword"),
                "usability_rating": request.form.get("usage-newpassword"),
                "password_log_guesses": log_guesses_newpassword,
                "password_entropy": entropy_newpassword,
                "password_similarity": similarity_newpassword or 0.0,
            }
        ]

        # Save feedback to the database
        for entry in feedback:
            feedback_entry = PasswordFeedback(
                password_type=entry["password_type"],
                password_value=entry["password_value"],
                memorable_rating=entry["memorable_rating"],
                usability_rating=entry["usability_rating"],
                password_log_guesses=entry["password_log_guesses"],
                password_entropy=entry["password_entropy"],
                password_similarity=entry["password_similarity"],
            )
            db.session.add(feedback_entry)
        db.session.commit()


        return redirect(url_for("success"))  # Redirect to results page

     # Handle GET request: Display feedback page
    if session.get("results"):
        results = session.get("results", {})
        long_password = results.get("long_password")
        result1 = results.get("result1")
        result2 = results.get("result2")
        result3 = results.get("result3")
        result4 = results.get("result4")
        result5 = results.get("result5")
        short_password = results.get("short_password")
        words = results.get("words", [])
        newpassword, log_guesses_newpassword, strength_newpassword = generate_strong_password(words)

        # Perform calculations
        strength1 = zxcvbn_strength(result1)
        strength2 = zxcvbn_strength(result2)
        strength3 = zxcvbn_strength(result3)
        strength4 = zxcvbn_strength(result4)
        strength5 = zxcvbn_strength(result5)
        long_strength = zxcvbn_strength(long_password)
        short_strength = zxcvbn_strength(short_password)
        strength_newpassword = zxcvbn_strength(newpassword)

    return render_template(
        'feedback.html', 
        result=result, 
        words=words, 
        short_password = short_password,
        long_password =long_password,
        result1=result1,
        result2=result2,
        result3=result3,
        result4=result4,
        result5=result5,
        strength1 = strength1,
        strength2 = strength2,
        strength3 = strength3,
        strength4 = strength4,
        strength5 = strength5,
        long_strength = long_strength,
        short_strength = short_strength,
        newpassword = newpassword,
        strength_newpassword = strength_newpassword,
        dropdown_options = {
            "memorable": ["Please Select","Extremely memorable", "Fairly memorable", "Somewhat difficult to remember", "Very difficult to remember"],
            "usage": ["Please Select","Definitely would use", "Probably would use", "Unlikely to use", "Definitely would not use"]
        },
        )
# Thank you page
@app.route('/success', methods=['GET'])
def success():
    return render_template('success.html')

@app.route('/results')
def results():
# Fetch all survey responses
    responses = SurveyResponse.query.all()
    # Group responses by question_id
    grouped_responses = {}
    for response in responses:
        if response.question_id not in grouped_responses:
            grouped_responses[response.question_id] = {
                "question_text": response.question_text,
                "answers": []
            }
        grouped_responses[response.question_id]["answers"].append(response.answer)

    # Determine the maximum number of answers for any question
    max_answers = max(len(data["answers"]) for data in grouped_responses.values()) if grouped_responses else 0

    # Fetch all stored user credentials
    credentials = UserCredentials.query.all()

    # Fetch all demographic data
    demographics = Demographics.query.all()
    

    # Fetch password feedback
    password_feedback = PasswordFeedback.query.all()


    return render_template(
        'results.html', 
        responses = responses,
        grouped_responses=grouped_responses, 
        password_feedback=password_feedback,
        credentials=credentials,
        demographics=demographics,
        max_answers=max_answers
    )

if __name__ == '__main__':
    app.run(debug=True)
