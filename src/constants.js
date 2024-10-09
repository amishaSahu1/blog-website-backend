export const DB_NAME = "consolebustersapi";

/**
 * @type {{ ADMIN: "ADMIN"; USER: "USER"; MODERATOR: "MODERATOR"; GUEST: "GUEST"; PREMIUM: "PREMIUM"} as const}
 */
export const UserRolesEnum = {
  ADMIN: "admin",
  USER: "user",
  MODERATOR: "moderator",
  GUEST: "guest",
  PREMIUM: "premium",
}; 

export const AvailableUserRoles = Object.values(UserRolesEnum);

/**
 * @type {{ 
*  ARTIFICIAL_INTELLIGENCE: "ARTIFICIAL_INTELLIGENCE";
*  MACHINE_LEARNING: "MACHINE_LEARNING";
*  DATA_SCIENCE: "DATA_SCIENCE";
*  BIG_DATA: "BIG_DATA";
*  BLOCKCHAIN: "BLOCKCHAIN";
*  CRYPTOCURRENCY: "CRYPTOCURRENCY";
*  CLOUD_COMPUTING: "CLOUD_COMPUTING";
*  CYBERSECURITY: "CYBERSECURITY";
*  INTERNET_OF_THINGS: "INTERNET_OF_THINGS";
*  AUGMENTED_REALITY: "AUGMENTED_REALITY";
*  VIRTUAL_REALITY: "VIRTUAL_REALITY";
*  MIXED_REALITY: "MIXED_REALITY";
*  QUANTUM_COMPUTING: "QUANTUM_COMPUTING";
*  SOFTWARE_DEVELOPMENT: "SOFTWARE_DEVELOPMENT";
*  WEB_DEVELOPMENT: "WEB_DEVELOPMENT";
*  MOBILE_DEVELOPMENT: "MOBILE_DEVELOPMENT";
*  GAME_DEVELOPMENT: "GAME_DEVELOPMENT";
*  DEVOPS: "DEVOPS";
*  AGILE_METHODOLOGIES: "AGILE_METHODOLOGIES";
*  DATA_STRUCTURES: "DATA_STRUCTURES";
*  ALGORITHMS: "ALGORITHMS";
*  COMPETITIVE_PROGRAMMING: "COMPETITIVE_PROGRAMMING";
*  PROGRAMMING_LANGUAGES: "PROGRAMMING_LANGUAGES";
*  JAVASCRIPT: "JAVASCRIPT";
*  PYTHON: "PYTHON";
*  JAVA: "JAVA";
*  C_SHARP: "C_SHARP";
*  C_PLUS_PLUS: "C_PLUS_PLUS";
*  RUBY: "RUBY";
*  PHP: "PHP";
*  SWIFT: "SWIFT";
*  KOTLIN: "KOTLIN";
*  GO: "GO";
*  RUST: "RUST";
*  TYPESCRIPT: "TYPESCRIPT";
*  HTML_CSS: "HTML_CSS";
*  REACT: "REACT";
*  ANGULAR: "ANGULAR";
*  VUE_JS: "VUE_JS";
*  SVELTE: "SVELTE";
*  NODE_JS: "NODE_JS";
*  DJANGO: "DJANGO";
*  FLASK: "FLASK";
*  SPRING_BOOT: "SPRING_BOOT";
*  ASP_NET: "ASP_NET";
*  LARAVEL: "LARAVEL";
*  RUBY_ON_RAILS: "RUBY_ON_RAILS";
*  MICROSERVICES: "MICROSERVICES";
*  API_DEVELOPMENT: "API_DEVELOPMENT";
*  DATABASE_MANAGEMENT: "DATABASE_MANAGEMENT";
*  SQL: "SQL";
*  NOSQL: "NOSQL";
*  MONGODB: "MONGODB";
*  POSTGRESQL: "POSTGRESQL";
*  MYSQL: "MYSQL";
*  SQLITE: "SQLITE";
*  FIREBASE: "FIREBASE";
*  GRAPHQL: "GRAPHQL";
*  RESTFUL_APIS: "RESTFUL_APIS";
*  TESTING_QA: "TESTING_QA";
*  UNIT_TESTING: "UNIT_TESTING";
*  INTEGRATION_TESTING: "INTEGRATION_TESTING";
*  END_TO_END_TESTING: "END_TO_END_TESTING";
*  AUTOMATION_TESTING: "AUTOMATION_TESTING";
*  CI_CD: "CI_CD";
*  CONTAINERIZATION: "CONTAINERIZATION";
*  DOCKER: "DOCKER";
*  KUBERNETES: "KUBERNETES";
*  SERVERLESS_ARCHITECTURE: "SERVERLESS_ARCHITECTURE";
*  NETWORK_SECURITY: "NETWORK_SECURITY";
*  ETHICAL_HACKING: "ETHICAL_HACKING";
*  PENETRATION_TESTING: "PENETRATION_TESTING";
*  DIGITAL_FORENSICS: "DIGITAL_FORENSICS";
*  CRYPTOGRAPHY: "CRYPTOGRAPHY";
*  INFORMATION_SECURITY: "INFORMATION_SECURITY";
*  ARTIFICIAL_NEURAL_NETWORKS: "ARTIFICIAL_NEURAL_NETWORKS";
*  NATURAL_LANGUAGE_PROCESSING: "NATURAL_LANGUAGE_PROCESSING";
*  COMPUTER_VISION: "COMPUTER_VISION";
*  REINFORCEMENT_LEARNING: "REINFORCEMENT_LEARNING";
*  ROBOTICS: "ROBOTICS";
*  AUTOMATION: "AUTOMATION";
*  CAREER_DEVELOPMENT: "CAREER_DEVELOPMENT";
*  FREELANCING: "FREELANCING";
*  REMOTE_WORK: "REMOTE_WORK";
*  TECH_INDUSTRY_NEWS: "TECH_INDUSTRY_NEWS";
*  STARTUP_CULTURE: "STARTUP_CULTURE";
*  ENTREPRENEURSHIP: "ENTREPRENEURSHIP";
*  E_LEARNING: "E_LEARNING";
*  ONLINE_COURSES: "ONLINE_COURSES";
*  EDTECH: "EDTECH";
*  PERSONAL_FINANCE: "PERSONAL_FINANCE";
*  INVESTING: "INVESTING";
*  STOCK_MARKET: "STOCK_MARKET";
*  REAL_ESTATE: "REAL_ESTATE";
*  PASSIVE_INCOME: "PASSIVE_INCOME";
*  SIDE_HUSTLES: "SIDE_HUSTLES";
* } as const
*/

export const AvailableBlogCategoryEnum = {
 ARTIFICIAL_INTELLIGENCE: "artificial-intelligence",
 MACHINE_LEARNING: "machine-learning",
 DATA_SCIENCE: "data-science",
 BIG_DATA: "big-data",
 BLOCKCHAIN: "blockchain",
 CRYPTOCURRENCY: "cryptocurrency",
 CLOUD_COMPUTING: "cloud-computing",
 CYBERSECURITY: "cybersecurity",
 INTERNET_OF_THINGS: "internet-of-things",
 AUGMENTED_REALITY: "augmented-reality",
 VIRTUAL_REALITY: "virtual-reality",
 MIXED_REALITY: "mixed-reality",
 QUANTUM_COMPUTING: "quantum-computing",
 SOFTWARE_DEVELOPMENT: "software-development",
 WEB_DEVELOPMENT: "web-development",
 MOBILE_DEVELOPMENT: "mobile-development",
 GAME_DEVELOPMENT: "game-development",
 DEVOPS: "devops",
 AGILE_METHODOLOGIES: "agile-methodologies",
 DATA_STRUCTURES: "data-structures",
 ALGORITHMS: "algorithms",
 COMPETITIVE_PROGRAMMING: "competitive-programming",
 PROGRAMMING_LANGUAGES: "programming-languages",
 JAVASCRIPT: "javascript",
 PYTHON: "python",
 JAVA: "java",
 C_SHARP: "c-sharp",
 C_PLUS_PLUS: "c-plus-plus",
 RUBY: "ruby",
 PHP: "php",
 SWIFT: "swift",
 KOTLIN: "kotlin",
 GO: "go",
 RUST: "rust",
 TYPESCRIPT: "typescript",
 HTML_CSS: "html-css",
 REACT: "react",
 ANGULAR: "angular",
 VUE_JS: "vue-js",
 SVELTE: "svelte",
 NODE_JS: "node-js",
 DJANGO: "django",
 FLASK: "flask",
 SPRING_BOOT: "spring-boot",
 ASP_NET: "asp-net",
 LARAVEL: "laravel",
 RUBY_ON_RAILS: "ruby-on-rails",
 MICROSERVICES: "microservices",
 API_DEVELOPMENT: "api-development",
 DATABASE_MANAGEMENT: "database-management",
 SQL: "sql",
 NOSQL: "nosql",
 MONGODB: "mongodb",
 POSTGRESQL: "postgresql",
 MYSQL: "mysql",
 SQLITE: "sqlite",
 FIREBASE: "firebase",
 GRAPHQL: "graphql",
 RESTFUL_APIS: "restful-apis",
 TESTING_QA: "testing-qa",
 UNIT_TESTING: "unit-testing",
 INTEGRATION_TESTING: "integration-testing",
 END_TO_END_TESTING: "end-to-end-testing",
 AUTOMATION_TESTING: "automation-testing",
 CI_CD: "ci-cd",
 CONTAINERIZATION: "containerization",
 DOCKER: "docker",
 KUBERNETES: "kubernetes",
 SERVERLESS_ARCHITECTURE: "serverless-architecture",
 NETWORK_SECURITY: "network-security",
 ETHICAL_HACKING: "ethical-hacking",
 PENETRATION_TESTING: "penetration-testing",
 DIGITAL_FORENSICS: "digital-forensics",
 CRYPTOGRAPHY: "cryptography",
 INFORMATION_SECURITY: "information-security",
 ARTIFICIAL_NEURAL_NETWORKS: "artificial-neural-networks",
 NATURAL_LANGUAGE_PROCESSING: "natural-language-processing",
 COMPUTER_VISION: "computer-vision",
 REINFORCEMENT_LEARNING: "reinforcement-learning",
 ROBOTICS: "robotics",
 AUTOMATION: "automation",
 CAREER_DEVELOPMENT: "career-development",
 FREELANCING: "freelancing",
 REMOTE_WORK: "remote-work",
 TECH_INDUSTRY_NEWS: "tech-industry-news",
 STARTUP_CULTURE: "startup-culture",
 ENTREPRENEURSHIP: "entrepreneurship",
 E_LEARNING: "e-learning",
 ONLINE_COURSES: "online-courses",
 EDTECH: "edtech",
 PERSONAL_FINANCE: "personal-finance",
 INVESTING: "investing",
 STOCK_MARKET: "stock-market",
 REAL_ESTATE: "real-estate",
 PASSIVE_INCOME: "passive-income",
 SIDE_HUSTLES: "side-hustles",
};

export const AvailableBlogCategory = Object.values(AvailableBlogCategoryEnum);